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
