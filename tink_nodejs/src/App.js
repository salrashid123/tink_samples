import React, {useEffect, useState} from "react";

import "./style.css";
import {aead,aeadSubtle, binary, binaryInsecure, KeysetHandle,mac,macSubtle,signature,signatureSubtle, generateNewKeysetHandle} from 'tink-crypto';

const {Aead, register, aes256GcmKeyTemplate, aes256GcmNoPrefixKeyTemplate } = aead;
const {Hmac} = mac;
register();

// https://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
function _arrayBufferToBase64( buffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return window.btoa( binary );
}

class Mac {
  constructor (key, data) {
    this.key = key;
    this.data = data;
  }

  async calcMac() {
    let ekey = new TextEncoder("utf-8").encode(this.key);
    const m = await macSubtle.hmacFromRawKey('SHA-256', ekey, 32);
    let edata = new TextEncoder("utf-8").encode(this.data);
    let computeMac = await m.computeMac(edata);
    let b64mac =_arrayBufferToBase64(computeMac);
    console.log(b64mac);
    return b64mac;
  }
}


export class MacForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hmac_key: "change this password to a secret",
      hmac_data: "foo",
      hmac_value: "",
    };
    this.handleChange = this.handleChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  handleChange(event) {
    this.setState({
      [event.target.name]: event.target.value
    });
  }

  handleSubmit(event) {
    event.preventDefault();
    let m = new Mac(this.state.hmac_key, this.state.hmac_data);
    m.calcMac().then((v => {

      this.setState({ hmac_value: v});
    }));
  }

  render() {
    const { items } = this.state;
    return (
      <form onSubmit={this.handleSubmit}>

        <div>      
        <label>
          key:
          <input type="text" value={this.state.hmac_key}   name="hmac_key" onChange={this.handleChange}/>
        </label>
        </div>

        <div>
        <label> 
          data:
          <input type="text" value={this.state.hmac_data}  name="hmac_data" onChange={this.handleChange} />                 
        </label>
        </div>

        <input type="submit" value="Submit" />
        <p><div id="mac_data" >{this.state.hmac_value}</div></p>

      </form>
     );
  }
}
