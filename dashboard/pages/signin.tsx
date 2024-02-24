// pages/signin.js
import { useState } from "react";
import axios from "axios";
import { Octokit } from "@octokit/core";

export default function SignIn() {
  const [token, setToken] = useState("");

  const generateToken = async () => {
    const { Octokit } = require("@octokit/core");

    const octokit = new Octokit({
      auth: process.env.GITHUB_TOKEN,
    });

    console.log(
      await octokit.request("GET /users/kygoben/repos", {
        headers: {
          "X-GitHub-Api-Version": "2022-11-28",
        },
      })
    );
    console.log("octokit", octokit);
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
