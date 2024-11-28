import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import Login from './components/Login';
import Home from './components/Home';
import PrivateRoute from './components/PrivateRoute';

function App() {
  return (
    <Router>
      <div className="App">
        <Switch>
          <Route path="/login" component={Login} />
          <PrivateRoute path="/home" component={Home} />
        </Switch>
      </div>
    </Router>
  );
}

export default App;
