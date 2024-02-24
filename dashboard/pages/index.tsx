import Link from "next/link"
import { Button } from "@/components/ui/button"
import { PopoverTrigger, PopoverContent, Popover } from "@/components/ui/popover"
import { CardTitle, CardDescription, CardHeader, CardContent, Card } from "@/components/ui/card"
import { DropdownMenuTrigger, DropdownMenuItem, DropdownMenuContent, DropdownMenu } from "@/components/ui/dropdown-menu"

export default function Component() {
  return (
    <div className="flex flex-col min-h-screen">
      <header className="flex items-center h-16 px-4 border-b shrink-0 md:px-6">
        <Link className="flex items-center gap-2 text-lg font-semibold sm:text-base mr-4" href="#">
          <FrameIcon className="w-6 h-6" />
          <span className="sr-only">Acme Inc</span>
        </Link>
        <nav className="hidden font-medium sm:flex flex-row items-center gap-5 text-sm lg:gap-6">
          <Link className="font-bold" href="#">
            Projects
          </Link>
          <Link className="text-gray-500 dark:text-gray-400" href="#">
            Deployments
          </Link>
          <Link className="text-gray-500 dark:text-gray-400" href="#">
            Analytics
          </Link>
          <Link className="text-gray-500 dark:text-gray-400" href="#">
            Logs
          </Link>
          <Link className="text-gray-500 dark:text-gray-400" href="#">
            Settings
          </Link>
        </nav>
        <div className="flex items-center w-full gap-4 md:ml-auto md:gap-2 lg:gap-4">
          <Popover>
            <PopoverTrigger asChild>
              <Button className="rounded-full ml-auto" variant="ghost">
                <img
                  alt="Avatar"
                  className="rounded-full border"
                  height="32"
                  src="/placeholder.svg"
                  style={{
                    aspectRatio: "32/32",
                    objectFit: "cover",
                  }}
                  width="32"
                />
                <span className="sr-only">Toggle user menu</span>
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end">
              <div>Profile</div>
              <div>Settings</div>
              <div />
              <div>Logout</div>
            </PopoverContent>
          </Popover>
        </div>
      </header>
      <main className="flex flex-1 flex-col p-4 md:p-10">
        <div className="max-w-6xl w-full mx-auto grid gap-2">
          <h1 className="font-semibold text-3xl">Fuzz Testing</h1>
          <p className="text-gray-500 dark:text-gray-400">Select a repository to start fuzz testing</p>
        </div>
        <div className="grid gap-6 max-w-6xl w-full mx-auto">
        {/* Example Repository Card */}
        <Card>
          <CardHeader className="flex flex-row items-center gap-4">
            <BookOpenIcon className="w-8 h-8" />
            <div className="grid gap-1">
              <CardTitle>Repository Name</CardTitle>
              <CardDescription>repository-url.com</CardDescription>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button className="ml-auto" size="icon" variant="ghost">
                  <MoreHorizontalIcon className="w-4 h-4" />
                  <span className="sr-only">Toggle menu</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem>View Project</DropdownMenuItem>
                <DropdownMenuItem>View Settings</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </CardHeader>
          <CardContent className="flex flex-row justify-between items-center">
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <GithubIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">Updated 3h ago</span>
              </div>
              <div className="flex items-center gap-1">
                <GitBranchIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">main</span>
              </div>
              <div className="flex items-center gap-1">
                {/* Status visual based on fuzz testing status */}
                <span className="bg-green-500 rounded-full h-4 w-4"></span>
                <span className="text-gray-500 dark:text-gray-400">Fuzz testing completed</span>
              </div>
            </div>
            {/* Additional stats and View Report button */}
            <div className="flex items-center gap-4 text-sm">
              <div className="flex flex-col items-end">
                <span className="text-gray-500 dark:text-gray-400">Functions analyzed: 50</span>
                <span className="text-gray-500 dark:text-gray-400">Total time: 2h</span>
              </div>
              <Button className="bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded">View Report</Button>
            </div>
          </CardContent>
        </Card>
        {/* Repository Card with no fuzz testing */}
        <Card>
          <CardHeader className="flex flex-row items-center gap-4">
            <BookOpenIcon className="w-8 h-8" />
            <div className="grid gap-1">
              <CardTitle>Repo 1</CardTitle>
              <CardDescription>repo1-url.com</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-2">
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <GithubIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">Updated 1 day ago</span>
              </div>
              <div className="flex items-center gap-1">
                <GitBranchIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">main</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="bg-gray-500 rounded-full h-4 w-4"></span>
                <span className="text-gray-500 dark:text-gray-400">No fuzz testing</span>
              </div>
            </div>
          </CardContent>
        </Card>
        {/* Repository Card with fuzz testing in progress */}
        <Card>
          <CardHeader className="flex flex-row items-center gap-4">
            <BookOpenIcon className="w-8 h-8" />
            <div className="grid gap-1">
              <CardTitle>Repo 2</CardTitle>
              <CardDescription>repo2-url.com</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-2">
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <GithubIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">Updated 2 hours ago</span>
              </div>
              <div className="flex items-center gap-1">
                <GitBranchIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">main</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="bg-yellow-500 rounded-full h-4 w-4"></span>
                <span className="text-gray-500 dark:text-gray-400">Fuzz testing in progress</span>
              </div>
            </div>
          </CardContent>
        </Card>
        {/* Repository Card with fuzz testing completed and vulnerabilities found */}
        <Card>
          <CardHeader className="flex flex-row items-center gap-4">
            <BookOpenIcon className="w-8 h-8" />
            <div className="grid gap-1">
              <CardTitle>Repo 3</CardTitle>
              <CardDescription>repo3-url.com</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-2">
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <GithubIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">Updated 5 days ago</span>
              </div>
              <div className="flex items-center gap-1">
                <GitBranchIcon className="w-4 h-4" />
                <span className="text-gray-500 dark:text-gray-400">main</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="bg-red-500 rounded-full h-4 w-4"></span>
                <span className="text-gray-500 dark:text-gray-400">Potential vulnerabilities found</span>
                {/* Number count of potential vulnerabilities, with warning symbol */}
                <span className="text-red-500 dark:text-red-400">3</span>
                {/* Additional stats for completed testing */}
                <span className="text-gray-500 dark:text-gray-400">Functions analyzed: 65</span>
                <span className="text-gray-500 dark:text-gray-400">Total time: 3h</span>
                <Button className="text-blue-500 dark:text-blue-400">View Report</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      </main>
    </div>
  )
}

function BookOpenIcon(props) {
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
      <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
      <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
    </svg>
  )
}


function FrameIcon(props) {
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
      <line x1="22" x2="2" y1="6" y2="6" />
      <line x1="22" x2="2" y1="18" y2="18" />
      <line x1="6" x2="6" y1="2" y2="22" />
      <line x1="18" x2="18" y1="2" y2="22" />
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


function GithubIcon(props) {
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
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  )
}


function HomeIcon(props) {
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
      <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      <polyline points="9 22 9 12 15 12 15 22" />
    </svg>
  )
}


function LayoutPanelLeftIcon(props) {
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
      <rect width="7" height="18" x="3" y="3" rx="1" />
      <rect width="7" height="7" x="14" y="3" rx="1" />
      <rect width="7" height="7" x="14" y="14" rx="1" />
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
