package multitenant

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"golang.org/x/net/context"

	"github.com/weaveworks/scope/app"
	"github.com/weaveworks/scope/common/xfer"
)

var longPollTime = aws.Int64(10)

// sqsControlRouter:
// Creates a queue for every probe that connects to it, and a queue for
// responses back to it.  When it recieves a request, posts it to the
// probe queue.  When probe recieves a request, handles it and posts the
// response back to the response queue.
type sqsControlRouter struct {
	service  *sqs.SQS
	queueURL *string

	mtx       sync.Mutex
	cond      *sync.Cond
	responses map[string]xfer.Response
}

type sqsRequestMessage struct {
	ID               string
	Request          xfer.Request
	ResponseQueueURL string
}

type sqsResponseMessage struct {
	ID       string
	Response xfer.Response
}

// NewSQSControlRouter the harbinger of death
func NewSQSControlRouter(url, region string, creds *credentials.Credentials) app.ControlRouter {
	result := &sqsControlRouter{
		service: sqs.New(session.New(aws.NewConfig().
			WithEndpoint(url).
			WithRegion(region).
			WithCredentials(creds))),
		queueURL:  nil,
		responses: map[string]xfer.Response{},
	}
	result.cond = sync.NewCond(&result.mtx)
	go result.loop()
	return result
}

func (cr *sqsControlRouter) Stop() error {
	_, err := cr.service.DeleteQueue(&sqs.DeleteQueueInput{
		QueueUrl: cr.getQueueURL(),
	})
	return err
}

func (cr *sqsControlRouter) setQueueURL(url *string) {
	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	cr.queueURL = url
}

func (cr *sqsControlRouter) getQueueURL() *string {
	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	return cr.queueURL
}

func (cr *sqsControlRouter) loop() {
	for {
		// this app gets an id, and has a return path for all responses from probes.
		// need to figure out a way of tidy up dead queues.
		name := fmt.Sprintf("control-app-%d", rand.Int63())
		queueURL, err := cr.service.CreateQueue(&sqs.CreateQueueInput{
			QueueName: aws.String(name),
		})
		// TODO deal with the queue already existing
		if err != nil {
			log.Printf("Failed to create queue: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		cr.setQueueURL(queueURL.QueueUrl)
		break
	}

	for {
		res, err := cr.service.ReceiveMessage(&sqs.ReceiveMessageInput{
			QueueUrl:        cr.queueURL,
			WaitTimeSeconds: longPollTime,
		})
		if err != nil {
			log.Printf("Error recieving message from %s: %v", *cr.queueURL, err)
			continue
		}
		if len(res.Messages) == 0 {
			continue
		}

		cr.handleResponses(res)
	}
}

func (cr *sqsControlRouter) handleResponses(res *sqs.ReceiveMessageOutput) {
	sqsResponses := []sqsResponseMessage{}
	for _, message := range res.Messages {
		var sqsResponse sqsResponseMessage
		if err := json.NewDecoder(bytes.NewBufferString(*message.Body)).Decode(&sqsResponse); err != nil {
			log.Printf("Error decoding message: %v", err)
			continue
		}
		sqsResponses = append(sqsResponses, sqsResponse)
	}

	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	for _, sqsResponse := range sqsResponses {
		cr.responses[sqsResponse.ID] = sqsResponse.Response
	}
	cr.cond.Broadcast()
}

func (cr *sqsControlRouter) waitForResponse(id string) xfer.Response {
	cr.mtx.Lock()
	defer cr.mtx.Unlock()
	for {
		response, ok := cr.responses[id]
		if ok {
			delete(cr.responses, id)
			return response
		}
		cr.cond.Wait()
	}
}

func (cr *sqsControlRouter) sendMessage(queueURL *string, message interface{}) error {
	buf := bytes.Buffer{}
	if err := json.NewEncoder(&buf).Encode(message); err != nil {
		return err
	}
	log.Printf("sendMessage to %s: %s", *queueURL, buf.String())
	_, err := cr.service.SendMessage(&sqs.SendMessageInput{
		QueueUrl:    queueURL,
		MessageBody: aws.String(buf.String()),
	})
	return err
}

func (cr *sqsControlRouter) Handle(_ context.Context, probeID string, req xfer.Request) (xfer.Response, error) {
	// Zeroth, make sure we've got a queue
	queueURL := cr.getQueueURL()
	if queueURL == nil {
		return xfer.Response{}, fmt.Errorf("No SQS queue yet!")
	}

	// First, get the queue url for the given probe.  This will tell us if the probe is connected.
	probeQueueName := fmt.Sprintf("probe-%s", probeID)
	probeQueueURL, err := cr.service.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: aws.String(probeQueueName),
	})
	if err != nil {
		return xfer.Response{}, err
	}

	// Next, send the request to that queue
	id := fmt.Sprintf("request-%d", rand.Int63())
	if err := cr.sendMessage(probeQueueURL.QueueUrl, sqsRequestMessage{
		ID:               id,
		Request:          req,
		ResponseQueueURL: *queueURL,
	}); err != nil {
		return xfer.Response{}, err
	}

	// Finally, wait for a response on our queue
	return cr.waitForResponse(id), nil
}

func (cr *sqsControlRouter) Register(_ context.Context, probeID string, handler xfer.ControlHandlerFunc) (int64, error) {
	// TODO can't reuse queue names for 60 secs.
	name := fmt.Sprintf("probe-%s", probeID)
	queueURL, err := cr.service.CreateQueue(&sqs.CreateQueueInput{
		QueueName: aws.String(name),
	})
	if err != nil {
		return 0, err
	}
	go func() {
		for { // TODO close these down cleanly
			res, err := cr.service.ReceiveMessage(&sqs.ReceiveMessageInput{
				QueueUrl:        queueURL.QueueUrl,
				WaitTimeSeconds: longPollTime,
			})
			if err != nil {
				log.Printf("[Probe %s] Error recieving message: %v", probeID, err)
				continue
			}
			if len(res.Messages) == 0 {
				continue
			}

			// TODO we need to parallelise the handling of requests
			for _, message := range res.Messages {
				var sqsRequest sqsRequestMessage
				if err := json.NewDecoder(bytes.NewBufferString(*message.Body)).Decode(&sqsRequest); err != nil {
					log.Printf("[Probe %s] Error decoding message from: %v", probeID, err)
					continue
				}

				if err := cr.sendMessage(&sqsRequest.ResponseQueueURL, sqsResponseMessage{
					ID:       sqsRequest.ID,
					Response: handler(sqsRequest.Request),
				}); err != nil {
					log.Printf("[Probe %s] Error sending response: %v", probeID, err)
				}
			}
		}
	}()
	return 0, nil
}

func (cr *sqsControlRouter) Deregister(_ context.Context, probeID string, id int64) error {
	return nil
	// TODO return the queue url and use that in delete
	//name := fmt.Sprintf("probe-%s", probeID)
	//_, err := cr.service.DeleteQueue(&sqs.DeleteQueueInput{
	//	QueueUrl: aws.String(name),
	//})
	//return err
}
