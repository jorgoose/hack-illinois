// pages/api/generate-token.js
import axios from 'axios';

export default async function handler(req, res) {
  try {
    const { data } = await axios.post(
      'https://api.github.com/authorizations',
      {
        scopes: ['repo'],
        note: 'PAT generated for my-github-signin app',
      },
      {
        auth: {
          username: process.env.GITHUB_USERNAME,
          password: process.env.GITHUB_PASSWORD,
        },
      }
    );
    res.status(200).json({ token: data.token });
  } catch (error) {
    console.error('Error generating token:', error.response.data);
    res.status(500).json({ error: 'Unable to generate token' });
  }
}
