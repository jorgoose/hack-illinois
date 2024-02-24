// pages/repo/[user]/[repo].js

import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import { Octokit } from "@octokit/core";

export default function RepoPage() {
  const router = useRouter();
  const { user, repo } = router.query;
  const [repository, setRepository] = useState(null);

  useEffect(() => {
    const fetchRepository = async () => {
      if (user && repo) {
        const octokit = new Octokit();
        try {
          const response = await octokit.request(`GET /repos/${user}/${repo}`);
          setRepository(response.data);
        } catch (error) {
          console.error('Error fetching repository:', error);
        }
      }
    };
    
    fetchRepository();
    console.log(user, repository);
  }, [user, repo]);

  if (!repository) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>{repository.full_name}</h1>
      <p>{repository.description}</p>
      <p>Owner: {repository.owner.login}</p>
      <p>Language: {repository.language}</p>
      <p>Stars: {repository.stargazers_count}</p>
      <p>Forks: {repository.forks_count}</p>
      {/* Add more details as needed */}
    </div>
  );
}
