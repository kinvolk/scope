import React from 'react';
import _ from 'lodash';

import { receiveNodesDelta } from '../actions/app-actions';
import AppStore from '../stores/app-store';
import Perf from 'react-addons-perf';

const sample = function(collection) {
  return _.range(_.random(4)).map(() => _.sample(collection));
};

const deltaAdd = function(name, adjacency = []) {
  return {
    'adjacency': adjacency,
    'controls': {},
    'id': name,
    'label_major': name,
    'label_minor': 'weave-1',
    'latest': {},
    'metadata': {},
    'origins': [],
    'rank': 'alpine'
  };
};

function stopPerf() {
  Perf.stop();
  const measurements = Perf.getLastMeasurements();
  Perf.printInclusive(measurements);
  Perf.printWasted(measurements);
}

function startPerf(delay) {
  Perf.start();
  setTimeout(stopPerf, delay * 1000);
}

function addNodes(n) {
  const ns = AppStore.getNodes();
  const nodeNames = ns.keySeq().toJS();
  const newNodeNames = _.range(ns.size, ns.size + n).map((i) => 'zing' + i);
  const allNodes = _(nodeNames).concat(newNodeNames).value();

  receiveNodesDelta({
    add: newNodeNames.map((name) => deltaAdd(name, sample(allNodes)))
  });
}

function hideToolbar() {
  //
  // Toggle with:
  // localStorage.debugToolbar = localStorage.debugToolbar ? '' : true;
  //
  delete localStorage.debugToolbar;
}

export function showingDebugToolbar() {
  return Boolean(localStorage.debugToolbar);
}

export class DebugToolbar extends React.Component {

  constructor(props, context) {
    super(props, context);
    this.onChange = this.onChange.bind(this);
    this.state = {
      nodesToAdd: 30
    };
  }

  onChange(ev) {
    this.setState({nodesToAdd: parseInt(ev.target.value, 10)});
  }

  render() {
    return (
      <div className="debug-panel">
        <div>
          <label>The debug toolbar!</label>
          <button onClick={hideToolbar}>&times;</button>
        </div>
        <div>
          <label>Add nodes </label>&nbsp;
          <button onClick={() => addNodes(1)}>+1</button>&nbsp;
          <button onClick={() => addNodes(10)}>+10</button>&nbsp;
          <input type="number" onChange={this.onChange} value={this.state.nodesToAdd} />&nbsp;
          <button onClick={() => addNodes(this.state.nodesToAdd)}>+</button>&nbsp;
        </div>
        <div>
          <label>Measure React perf for </label>
          <button onClick={() => startPerf(2)}>2s</button>
          <button onClick={() => startPerf(5)}>5s</button>
          <button onClick={() => startPerf(10)}>10s</button>
        </div>
      </div>
    );
  }
}
