package multitenant

import (
	"bytes"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"golang.org/x/net/context"

	"github.com/weaveworks/scope/app"
	"github.com/weaveworks/scope/report"
)

//https://github.com/aws/aws-sdk-go/wiki/common-examples

const (
	tableName   = "reports"
	hourField   = "hour"
	tsField     = "ts"
	reportField = "report"
)

type dynamoDBCollector struct {
	db *dynamodb.DynamoDB
}

// NewDynamoDBCollector the reaper of souls
func NewDynamoDBCollector(url, region string, creds *credentials.Credentials) app.Collector {
	result := &dynamoDBCollector{
		db: dynamodb.New(session.New(aws.NewConfig().
			WithEndpoint(url).
			WithRegion(region).
			WithCredentials(creds))),
	}

	// There is a race here, so try 10 times to create the table
	for i := 0; i < 10; i++ {
		if err := result.createTable(); err != nil {
			log.Printf("Error creating table: %v", err)
			continue
		}
		break
	}

	return result
}

func (c *dynamoDBCollector) createTable() error {
	resp, err := c.db.ListTables(&dynamodb.ListTablesInput{
		Limit: aws.Int64(10),
	})
	if err != nil {
		return err
	}

	// see if tableName exists
	for _, s := range resp.TableNames {
		if *s == tableName {
			log.Printf("Found table %s", *s)
			return nil
		}
	}

	params := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String(hourField),
				AttributeType: aws.String("N"),
			},
			{
				AttributeName: aws.String(tsField),
				AttributeType: aws.String("N"),
			},
			// Don't need to specify non-key attributes in schema
			//{
			//	AttributeName: aws.String(reportField),
			//	AttributeType: aws.String("B"),
			//},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String(hourField),
				KeyType:       aws.String("HASH"),
			},
			{
				AttributeName: aws.String(tsField),
				KeyType:       aws.String("RANGE"),
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(5),
		},
	}
	log.Printf("Creating table %s", tableName)
	_, err = c.db.CreateTable(params)
	return err
}

func (c *dynamoDBCollector) Report(context.Context) report.Report {
	now := time.Now()
	start := now.Add(-15 * time.Second)

	resp, err := c.db.Query(&dynamodb.QueryInput{
		TableName: aws.String(tableName),

		KeyConditions: map[string]*dynamodb.Condition{
			hourField: {
				AttributeValueList: []*dynamodb.AttributeValue{
					{N: aws.String(strconv.FormatInt(start.Unix()/3600, 10))},
				},
				ComparisonOperator: aws.String("EQ"),
			},
			tsField: {
				AttributeValueList: []*dynamodb.AttributeValue{
					{N: aws.String(strconv.FormatInt(start.UnixNano(), 10))},
					{N: aws.String(strconv.FormatInt(now.UnixNano(), 10))},
				},
				ComparisonOperator: aws.String("BETWEEN"),
			},
		},
	})
	if err != nil {
		log.Printf("Error collecting report: %v", err)
		return report.MakeReport()
	}

	log.Printf("Got %d reports", *resp.Count)
	result := report.MakeReport()
	for _, item := range resp.Items {
		b := item[reportField].B
		if b == nil {
			log.Printf("Empty row!")
			continue
		}

		buf := bytes.NewBuffer(b)
		rep := report.MakeReport()
		if err := json.NewDecoder(buf).Decode(&rep); err != nil {
			log.Printf("Failed to decode report: %v", err)
			continue
		}

		result = result.Merge(rep)
	}
	return result
}

func (c *dynamoDBCollector) Add(_ context.Context, rep report.Report) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(rep); err != nil {
		panic(err)
	}

	now := time.Now()
	_, err := c.db.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item: map[string]*dynamodb.AttributeValue{
			hourField: {
				N: aws.String(strconv.FormatInt(now.Unix()/3600, 10)),
			},
			tsField: {
				N: aws.String(strconv.FormatInt(now.UnixNano(), 10)),
			},
			reportField: {
				B: buf.Bytes(),
			},
		},
	})
	if err != nil {
		log.Printf("Error inserting report: %v", err)
	}
}

func (c *dynamoDBCollector) WaitOn(context.Context, chan struct{}) {}

func (c *dynamoDBCollector) UnWait(context.Context, chan struct{}) {}
