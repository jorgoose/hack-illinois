// pages/signin.js
import { useState } from 'react';
import axios from 'axios';

export default function SignIn() {
  const [token, setToken] = useState('');

  const generateToken = async () => {
    try {
      const response = await axios.post('/api/generate-token');
      setToken(response.data.token);
    } catch (error) {
      console.error('Error generating token:', error);
    }
  };

  return (
    <div>
      <h1>Sign In to GitHub</h1>
      {token ? (
        <div>
          <p>Personal Access Token generated:</p>
          <code>{token}</code>
        </div>
      ) : (
        <button onClick={generateToken}>Generate Token</button>
      )}
    </div>
  );
}
