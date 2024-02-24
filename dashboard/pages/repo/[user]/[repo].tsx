// pages/repo/[user]/[repo].js

import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import { Octokit } from "@octokit/core";
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { Button } from "@/components/ui/button"
import { DropdownMenuTrigger, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuContent, DropdownMenu } from "@/components/ui/dropdown-menu"

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
    <div className="flex flex-col min-h-screen">
      <div className="border-b bg-white dark:bg-gray-950 border-gray-100/40 dark:border-gray-800/40">
        <div className="max-w-6xl w-full mx-auto grid gap-2 items-center min-h-[4rem] sm:grid-cols-[1fr_auto] sm:gap-4 py-4 px-4 md:grid-cols-[1fr_auto_1fr] md:gap-8">
          <div className="flex items-center gap-2 text-xl font-semibold">
            <TerminalIcon className="w-6 h-6" />
            <h1 className="text-2xl font-bold">Fuzz Testing</h1>
          </div>
          <nav className="flex items-center justify-end gap-4 text-sm md:gap-6">
            <div className="flex items-center gap-2">
              <CalendarClockIcon className="w-4 h-4" />
              <span className="font-medium">Tests</span>
            </div>
            <div className="flex items-center gap-2">
              <FileIcon className="w-4 h-4" />
              <span className="font-medium">Coverage</span>
            </div>
            <div className="flex items-center gap-2">
              <AlertTriangleIcon className="w-4 h-4" />
              <span className="font-medium">Issues</span>
            </div>
          </nav>
        </div>
      </div>
      <div className="flex-1 bg-gray-100/40 dark:bg-gray-800/40">
        <div className="max-w-6xl w-full mx-auto grid gap-4 p-4 md:gap-8 md:p-10">
          <div className="grid gap-2">
            <h1 className="font-semibold text-3xl">Tests</h1>
          </div>
          <div className="grid gap-6">
            <div className="flex flex-col lg:flex-row bg-white p-4 rounded-lg shadow-sm dark:bg-gray-950">
              <div className="grid gap-1 flex-1">
                <div className="font-semibold">AdIqWrked</div>
                <div className="text-gray-500 dark:text-gray-400">
                  Production
                  <Badge className="bg-white dark:bg-gray-950" variant="outline">
                    Current
                  </Badge>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-start gap-2">
                  <span className="inline-flex w-3 h-3 bg-green-400 rounded-full translate-y-1" />
                  <div>
                    Ready
                    <div className="text-gray-500 dark:text-gray-400">2m 35s</div>
                  </div>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2">
                  <GitBranchIcon className="w-4 h-4" />
                  main
                </div>
                <div className="flex items-center gap-2">
                  <GitCommitIcon className="w-4 h-4" />
                  <span className="line-clamp-1">fix: auth issues for third-party integration</span>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400">17m ago by shadcn</div>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button className="absolute top-4 right-4" size="icon" variant="ghost">
                    <MoreHorizontalIcon className="w-4 h-4" />
                    <span className="sr-only">Toggle menu</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem>View Deployment</DropdownMenuItem>
                  <DropdownMenuItem>Redeploy</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem disabled>Rollback</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="flex flex-col lg:flex-row bg-white p-4 rounded-lg shadow-sm dark:bg-gray-950">
              <div className="grid gap-1 flex-1">
                <div className="font-semibold">PMVpfLNj</div>
                <div className="text-gray-500 dark:text-gray-400">Preview</div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-start gap-2">
                  <span className="inline-flex w-3 h-3 bg-green-400 rounded-full translate-y-1" />
                  <div>
                    Ready
                    <div className="text-gray-500 dark:text-gray-400">1m 23s</div>
                  </div>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2">
                  <GitBranchIcon className="w-4 h-4" />
                  max/logging
                </div>
                <div className="flex items-center gap-2">
                  <GitCommitIcon className="w-4 h-4" />
                  <span className="line-clamp-1">feat: implement action logging</span>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400">32m ago by maxleiter</div>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button className="absolute top-4 right-4" size="icon" variant="ghost">
                    <MoreHorizontalIcon className="w-4 h-4" />
                    <span className="sr-only">Toggle menu</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem>View Deployment</DropdownMenuItem>
                  <DropdownMenuItem>Redeploy</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem disabled>Rollback</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="flex flex-col lg:flex-row bg-white p-4 rounded-lg shadow-sm dark:bg-gray-950">
              <div className="grid gap-1 flex-1">
                <div className="font-semibold">YP47Kdjb</div>
                <div className="text-gray-500 dark:text-gray-400">Preview</div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-start gap-2">
                  <span className="inline-flex w-3 h-3 bg-red-400 rounded-full translate-y-1" />
                  <div>
                    Failed
                    <div className="text-gray-500 dark:text-gray-400">4m 22s</div>
                  </div>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2">
                  <GitBranchIcon className="w-4 h-4" />
                  shadcn/history-sidebar
                </div>
                <div className="flex items-center gap-2">
                  <GitCommitIcon className="w-4 h-4" />
                  <span className="line-clamp-1">feat: implement history sidebar</span>
                </div>
              </div>
              <Separator className="my-2 lg:my-0" />
              <div className="grid gap-1 flex-1">
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400">1 day ago by shadcn</div>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button className="absolute top-4 right-4" size="icon" variant="ghost">
                    <MoreHorizontalIcon className="w-4 h-4" />
                    <span className="sr-only">Toggle menu</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem>View Deployment</DropdownMenuItem>
                  <DropdownMenuItem>Redeploy</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem disabled>Rollback</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function AlertTriangleIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  )
}


function CalendarClockIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5" />
      <path d="M16 2v4" />
      <path d="M8 2v4" />
      <path d="M3 10h5" />
      <path d="M17.5 17.5 16 16.25V14" />
      <path d="M22 16a6 6 0 1 1-12 0 6 6 0 0 1 12 0Z" />
    </svg>
  )
}


function FileIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
      <polyline points="14 2 14 8 20 8" />
    </svg>
  )
}


function GitBranchIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="6" x2="6" y1="3" y2="15" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </svg>
  )
}


function GitCommitIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <line x1="3" x2="9" y1="12" y2="12" />
      <line x1="15" x2="21" y1="12" y2="12" />
    </svg>
  )
}


function MoreHorizontalIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="1" />
      <circle cx="19" cy="12" r="1" />
      <circle cx="5" cy="12" r="1" />
    </svg>
  )
}


function TerminalIcon(props) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" x2="20" y1="19" y2="19" />
    </svg>
  )
}
