import React, { Component } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';

import { EMPTY_FUNCTION } from '../../Constants/PropTypes';
import Alert from '../../Components/Alert/Alert';
import { auth } from '../sagas';

import { initialState } from '../reducer';

export class TokenValidation extends Component {
  // Check for token on component mount.
  // The token is never read from the URL; it is retrieved from the
  // server, which stores it in an httpOnly cookie.
  componentWillMount() {
    // First check if a token exists in local auth storage.
    const storedToken = auth.get();
    if (storedToken) {
      this.props.tokenValidationRequest(storedToken);
      return;
    }
    // Otherwise, ask the middle tier for the token from the httpOnly cookie.
    const tokenEndpoint = `${process.env.PUBLIC_URL || '/talentmap'}/tokenValidation/token`.replace('//', '/');
    axios.get(tokenEndpoint, { withCredentials: true })
      .then(response => this.props.tokenValidationRequest(response.data.token))
      .catch(() => this.props.tokenValidationRequest(null));
  }

  render() {
    const {
      login: {
        requesting,
        messages,
        errors,
      },
    } = this.props;

    return (
      <div className="usa-grid-full login-container content-container padded-main-content">
        <div className="usa-grid-full login">
          <div className="auth-messages">
            {
              !requesting && !!errors.length &&
              (<div className="usa-width-one-half">
                <Alert title="Failed to login due to:" messages={errors} type="error" />
              </div>)
            }
            {
              !requesting && !!messages.length &&
              (<div className="usa-width-one-half">
                <Alert title="Please see below" messages={messages} type="info" />
              </div>)
            }
            {
              requesting &&
              (<div className="usa-width-one-half">
                <Alert title="Logging in..." type="info" />
              </div>)
            }
          </div>
        </div>
      </div>
    );
  }
}

TokenValidation.propTypes = {
  tokenValidationRequest: PropTypes.func,
  login: PropTypes.shape({
    requesting: PropTypes.bool,
    successful: PropTypes.bool,
    messages: PropTypes.array,
    errors: PropTypes.array,
  }).isRequired,
};

TokenValidation.defaultProps = {
  tokenValidationRequest: EMPTY_FUNCTION,
  login: initialState,
};

export default TokenValidation;
