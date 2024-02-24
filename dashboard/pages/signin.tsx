// pages/signin.js
import { useState } from "react";
import axios from "axios";
import { Octokit } from "@octokit/core";

export default function SignIn() {
  const [token, setToken] = useState("");

  const generateToken = async () => {
    const { Octokit } = require("@octokit/core");

    const octokit = new Octokit({
      auth: "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",
    });

    console.log(
      await octokit.request("GET /user/repos", {
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
