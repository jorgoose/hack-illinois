// pages/repo/[user]/[repo].js

import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import { Octokit } from "@octokit/core";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Database } from "@/supabase";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  DropdownMenuTrigger,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuContent,
  DropdownMenu,
} from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableRow, TableCell } from "@/components/ui/table";
import { createClient } from "@supabase/supabase-js";

type Test = Database["public"]["Tables"]["tests"]["Row"];

export default function RepoPage() {
  const router = useRouter();
  const { user, repo } = router.query;
  const [repository, setRepository] = useState(null);
  const [coverage, setCoverage] = useState(false);
  const [tests, setTests] = useState<Test[]>([]);

  const supabaseUrl = "https://enobxhmkgvnegrpndfqn.supabase.co";
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_KEY!;

  const supabase = createClient<Database>(supabaseUrl, supabaseKey);

  useEffect(() => {
    const fetchRepository = async () => {
      if (user && repo) {
        const octokit = new Octokit();
        try {
          const response = await octokit.request(`GET /repos/${user}/${repo}`);
          setRepository(response.data);
        } catch (error) {
          console.error("Error fetching repository:", error);
        }
      }
    };

    const fetchTests = async () => {
      let { data: tests, error } = await supabase
        .from("tests")
        .select("*")
        .eq("repo", "ultra-secure-python-code");
      setTests(tests || []);
      console.log(tests, error);
    };

    fetchRepository();

    fetchTests();

    console.log(user, repository);
    console.log(tests);
  }, [user, repo]);

  if (!repository) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex flex-col min-h-screen">
      <div>
        <div className="border-b bg-white dark:bg-gray-950 border-gray-100/40">
          <div className="max-w-6xl w-full mx-auto grid gap-2 items-center min-h-[4rem] sm:grid-cols-[1fr_auto] sm:gap-4 py-4 px-4 md:grid-cols-[1fr_auto_1fr] md:gap-8">
            <div className="flex items-center gap-2 text-xl font-semibold">
              <TerminalIcon className="w-6 h-6" />
              <h1 className="text-2xl font-bold">Fuzz Testing</h1>
            </div>
            <nav className="flex items-center justify-end gap-4 text-sm md:gap-6">
              <div className="flex items-center gap-2">
                <CalendarClockIcon className="w-4 h-4" />
                <span
                  className="font-medium"
                  onClick={() => setCoverage(false)}
                  style={{ cursor: "pointer" }}
                >
                  Tests
                </span>
              </div>
              <div className="flex items-center gap-2">
                <FileIcon className="w-4 h-4" />
                <span
                  className="font-medium"
                  onClick={() => setCoverage(true)}
                  style={{ cursor: "pointer" }}
                >
                  Coverage
                </span>
              </div>
              {/* <div className="flex items-center gap-2">
              <AlertTriangleIcon className="w-4 h-4" />
              <span className="font-medium">Issues</span>
            </div> */}
            </nav>
          </div>
        </div>
        {coverage && (
          <div className="flex flex-col gap-4 p-4">
            <h1 className="text-2xl font-semibold tracking-tighter">
              Code Coverage Report
            </h1>
            <div className="flex items-center gap-4">
              <div className="flex flex-col gap-1.5">
                <h2 className="text-base font-medium tracking-tighter">
                  Overall Code Coverage
                </h2>
                <p className="text-3xl font-bold tracking-tighter">87%</p>
              </div>
              <div className="w-1/3">
                {/* Placeholder for any additional content */}
              </div>
            </div>
            <div className="flex flex-col gap-4">
              <Card>
                <div className="grid w-full p-4 gap-4 text-xs md:grid-cols-[1fr_100px_100px_100px_100px] lg:grid-cols-[1fr_100px_100px_100px_100px]">
                  <div className="font-medium">File</div>
                  <div className="font-medium">Statements</div>
                  <div className="font-medium">Branches</div>
                  <div className="font-medium">Functions</div>
                  <div className="font-medium">Lines</div>
                  <div className="font-medium">Coverage</div>
                  <div className="font-medium">Branches</div>
                  <div className="font-medium">Functions</div>
                  <div className="font-medium">Lines</div>
                  <div>src/index.js</div>
                  <div>80%</div>
                  <div>90%</div>
                  <div>70%</div>
                  <div>75%</div>
                  <div className="flex items-center gap-2">
                    <CheckCircleIcon className="w-4 h-4 text-green-500" />
                    <span>80%</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircleIcon className="w-4 h-4 text-green-500" />
                    <span>90%</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircleIcon className="w-4 h-4 text-green-500" />
                    <span>70%</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircleIcon className="w-4 h-4 text-green-500" />
                    <span>75%</span>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        )}
        {!coverage && (
          <div className="flex-1 bg-gray-100/40 dark:bg-gray-800/40 p-4">
            <div className="max-w-6xl w-full mx-auto grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader className="flex flex-row items-center gap-4">
                  <BoxIcon className="w-8 h-8" />
                  <div className="grid gap-1">
                    <CardTitle>Test Suite</CardTitle>
                    <CardDescription>Integration Tests</CardDescription>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button className="ml-auto" size="icon" variant="ghost">
                        <MoreHorizontalIcon className="w-4 h-4" />
                        <span className="sr-only">Toggle menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem>View Suite</DropdownMenuItem>
                      <DropdownMenuItem>Run Again</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </CardHeader>
                <CardContent className="grid gap-2">
                  <div className="grid gap-2">
                    <div className="grid grid-cols-2 items-center gap-2">
                      <div>Tests</div>
                      <div className="text-right">{tests.length}</div>
                    </div>
                    <div className="grid grid-cols-2 items-center gap-2">
                      <div>Passed</div>
                      <div className="text-right">
                        {tests.filter((test) => test.status === "PASS").length}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 items-center gap-2">
                      <div>Failed</div>
                      <div className="text-right">
                        {tests.filter((test) => test.status === "FAIL").length}
                      </div>
                    </div>
                  </div>
                  <div />
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center gap-4">
                  <AlertTriangleIcon className="w-8 h-8" />
                  <div className="grid gap-1">
                    <CardTitle>Issues Found</CardTitle>
                    <CardDescription>Security Vulnerabilities</CardDescription>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button className="ml-auto" size="icon" variant="ghost">
                        <MoreHorizontalIcon className="w-4 h-4" />
                        <span className="sr-only">Toggle menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem>View Issues</DropdownMenuItem>
                      <DropdownMenuItem>Resolve</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </CardHeader>
                <CardContent className="grid gap-2">
                  <div className="grid grid-cols-2 items-center gap-2">
                    <div>High</div>
                    <div className="text-right">2</div>
                  </div>
                  <div className="grid grid-cols-2 items-center gap-2">
                    <div>Medium</div>
                    <div className="text-right">3</div>
                  </div>
                  <div className="grid grid-cols-2 items-center gap-2">
                    <div>Low</div>
                    <div className="text-right">1</div>
                  </div>
                </CardContent>
              </Card>
            </div>
            <div className="max-w-6xl w-full mx-auto grid gap-4 md:grid-cols-1">
              <div className="max-w-6xl w-full mx-auto grid gap-4 md:grid-cols-1">
                {tests &&
                  tests.map((test, index) => (
                    <Card key={index}>
                      <CardHeader className="flex flex-row items-center gap-4">
                        <GitCommitIcon className="w-8 h-8" />
                        <div className="grid gap-1">
                          <CardTitle>{test.name}</CardTitle>
                          <CardDescription>
                            Time Elapsed: {test.time} seconds
                          </CardDescription>
                        </div>
                      <div>Status: {test.status}</div>
                      </CardHeader>
                      
                      <div className="flex flex-col items-center justify-center w-full h-full gap-4">
                        <Card className="w-full max-w-3xl p-0 items-center">
                          <CardContent className="p-0">
                            <div className="border-b">
                              <div className="grid items-center grid-cols-1 p-4 md:grid-cols-2 md:gap-4 md:p-6">
                                <div className="flex items-center gap-2 text-lg font-semibold md:gap-1">
                                  <FileTextIcon className="h-6 w-6" />
                                  <h1 className="text-xl font-bold">
                                    {test.name}
                                  </h1>
                                </div>
                                <div className="flex items-center justify-end md:justify-start">
                                  <Badge className="text-sm" variant="outline">
                                    {test.status}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="p-4 border-b md:p-6">
                              <div className="grid gap-2 md:gap-1.5">
                                <div className="grid items-center grid-cols-1 md:grid-cols-2 md:gap-2">
                                  <div className="text-sm font-medium md:text-base">
                                    Execution Time
                                  </div>
                                  <div className="flex items-center justify-end text-sm md:text-right md:gap-2">
                                    <span>{test.time}s</span>
                                  </div>
                                </div>
                                <div className="grid items-center grid-cols-1 md:grid-cols-2 md:gap-2">
                                  <div className="text-sm font-medium md:text-base">
                                    Potential Reasons for Failure
                                  </div>
                                  <div className="flex items-center justify-end text-sm md:text-right md:gap-2">
                                    <ul className="list-disc list-inside text-sm md:text-base">
                                      <li>Invalid input data</li>
                                      <li>Assertion error in line 42</li>
                                    </ul>
                                  </div>
                                </div>
                              </div>
                            </div>
                            <div className="p-4 md:p-6">
                              <Card>
                                <CardContent className="p-0">
                                  <Table className="border-0">
                                    <TableBody>
                                      <TableRow>
                                        <TableCell className="font-medium">
                                          Input
                                        </TableCell>
                                        <TableCell className="whitespace-pre-line">
                                          {test.test}
                                        </TableCell>
                                      </TableRow>
                                      <TableRow>
                                        <TableCell className="font-medium">
                                          Output
                                        </TableCell>
                                        <TableCell className="whitespace-pre-line">
                                          {test.output}
                                        </TableCell>
                                      </TableRow>
                                    </TableBody>
                                  </Table>
                                </CardContent>
                              </Card>
                            </div>
                            <div className="p-4 md:p-6">
                              <Card>
                                <CardHeader className="border-b">
                                  <CardTitle>Stack Trace</CardTitle>
                                </CardHeader>
                                <CardContent>
                                  <pre className="text-xs p-4 rounded-md bg-gray-50 dark:bg-gray-800">
                                    AssertionError: expected true to be false at
                                    Context.it (/test/test_parse.js:6:12) at
                                    callFn
                                  </pre>
                                </CardContent>
                              </Card>
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                    </Card>
                  ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface IconProps {
  className?: string;
  onClick?: () => void;
}

function AlertTriangleIcon(props: IconProps) {
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
  );
}
function CheckCircleIcon(props: IconProps) {
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
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}

function CalendarClockIcon(props: IconProps) {
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
  );
}

function FileIcon(props: IconProps) {
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
  );
}

function GitCommitIcon(props: IconProps) {
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
  );
}

function MoreHorizontalIcon(props: IconProps) {
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
  );
}

function TerminalIcon(props: IconProps) {
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
  );
}

function BoxIcon(props: IconProps) {
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
      <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
      <path d="m3.3 7 8.7 5 8.7-5" />
      <path d="M12 22V12" />
    </svg>
  );
}

function FileTextIcon(props: any) {
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
      <line x1="16" x2="8" y1="13" y2="13" />
      <line x1="16" x2="8" y1="17" y2="17" />
      <line x1="10" x2="8" y1="9" y2="9" />
    </svg>
  );
}
