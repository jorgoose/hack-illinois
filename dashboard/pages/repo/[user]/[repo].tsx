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
        <div className="border-b bg-gradient-to-r from-gray-700 via-gray-900 to-black text-white">
          <div className="max-w-6xl w-full mx-auto grid gap-2 items-center min-h-[4rem] sm:grid-cols-[1fr_auto] sm:gap-4 py-4 px-4 md:grid-cols-[1fr_auto_1fr] md:gap-8">
            <div className="flex items-center gap-2 text-xl font-semibold">
              <ShieldIcon className="w-6 h-6 text-cyan-500" />
              <h1 className="text-2xl font-bold ml-4">Fuzz<span className="text-cyan-500">Guard</span></h1>
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
  <div className="flex-1 bg-gray-800 p-4 text-white">
    <div className="max-w-6xl w-full mx-auto grid gap-4 md:grid-cols-2">
      {/* Card components for Test Suite and Issues Found... */}
    </div>
    <div className="max-w-6xl w-full mx-auto grid gap-4 md:grid-cols-1">
      {tests &&
        tests.map((test, index) => (
          <Card key={index} className="bg-gray-900 shadow-xl rounded-lg p-6">
            <CardHeader className="flex flex-row items-center gap-4">
              <GitCommitIcon className="w-8 h-8 text-green-500" />
              <div className="grid gap-1">
                <CardTitle className="text-xl font-semibold">{test.name}</CardTitle>
                <CardDescription className="text-gray-400">
                  Time Elapsed: {test.time} seconds
                </CardDescription>
              </div>
              <div className={`text-sm font-medium ${test.status === "PASS" ? "text-green-500" : "text-red-500"}`}>
                Status: {test.status}
              </div>
            </CardHeader>
            <CardContent className="grid gap-6">
              <div className="grid gap-4">
                <div className="grid grid-cols-2 items-center gap-2">
                  <div className="text-sm font-medium">Execution Time</div>
                  <div className="text-right">{test.time}s</div>
                </div>
                <div className="grid grid-cols-2 items-center gap-2">
                  <div className="text-sm font-medium">Potential Reasons for Failure</div>
                  <div className="text-right">
                    <ul className="list-disc list-inside text-sm">
                      <li>Invalid input data</li>
                      <li>Assertion error in line 42</li>
                    </ul>
                  </div>
                </div>
              </div>
              <details className="bg-gray-800 rounded-lg p-4">
                <summary className="cursor-pointer font-medium">Generated Test Code</summary>
                <pre className="text-xs p-4 rounded-md bg-gray-700 mt-4 whitespace-pre-wrap">
                  {test.test}
                </pre>
              </details>
              <div>
                <Card className="bg-gray-800 rounded-lg p-4">
                  <CardContent className="grid gap-4">
                    <div className="grid grid-cols-2 items-center gap-2">
                      <div className="font-medium">Output</div>
                      <div className="whitespace-pre-line">{test.output}</div>
                    </div>
                  </CardContent>
                </Card>
              </div>
              <div>
                <Card className="bg-gray-800 rounded-lg p-4">
                  <CardHeader className="border-b mb-4">
                    <CardTitle className="text-lg font-semibold">stdout</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="text-xs p-4 rounded-md bg-gray-700 whitespace-pre-wrap">
                      {test.stdout ? test.stdout : "Empty stdout implies fuzzing did not encounter any potential vulnerabilities"}
                    </pre>
                  </CardContent>
                </Card>
              </div>
            </CardContent>
          </Card>
        ))}
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

function ShieldIcon(props: IconProps) {
  return (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2L4 6V12C4 16.42 7.79 20.5 12 22C16.21 20.5 20 16.42 20 12V6L12 2Z" /> {/* Shield */}
      <g transform="scale(0.05) translate(145, 215)"> {/* Smiley, scaled and positioned to fit in the shield */}
        <circle cx="41" cy="32" r="15" fill="currentColor" /> {/* Left eye */}
        <circle cx="147" cy="32" r="15" fill="currentColor" /> {/* Right eye */}
        <path d="M50 80 Q 95 150 140 80" fill="none" stroke="currentColor" strokeWidth="25" /> {/* Mouth */}      
      </g>
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
