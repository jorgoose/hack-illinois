import { Badge } from "@/components/ui/badge"
import { TableCell, TableRow, TableBody, Table } from "@/components/ui/table"
import { CardContent, Card, CardTitle, CardHeader } from "@/components/ui/card"

export default function Component() {
  return (
    <Card className="w-full max-w-3xl p-0">
      <CardContent className="p-0">
        <div className="border-b">
          <div className="grid items-center grid-cols-1 p-4 md:grid-cols-2 md:gap-4 md:p-6">
            <div className="flex items-center gap-2 text-lg font-semibold md:gap-1">
              <FileTextIcon className="h-6 w-6" />
              <h1 className="text-xl font-bold">test_parse.js</h1>
            </div>
            <div className="flex items-center justify-end md:justify-start">
              <Badge className="text-sm" variant="outline">
                Test Passed
              </Badge>
            </div>
          </div>
        </div>
        <div className="p-4 border-b md:p-6">
          <div className="grid gap-2 md:gap-1.5">
            <div className="grid items-center grid-cols-1 md:grid-cols-2 md:gap-2">
              <div className="text-sm font-medium md:text-base">Execution Time</div>
              <div className="flex items-center justify-end text-sm md:text-right md:gap-2">
                <span>5.2s</span>
              </div>
            </div>
            <div className="grid items-center grid-cols-1 md:grid-cols-2 md:gap-2">
              <div className="text-sm font-medium md:text-base">Potential Reasons for Failure</div>
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
                    <TableCell className="font-medium">Input</TableCell>
                    <TableCell className="whitespace-pre-line">
                      {`{
                    "name": "John Doe",
                    "age": 30
                  }`}
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium">Output</TableCell>
                    <TableCell className="whitespace-pre-line">
                      {`{
                    "name": "John Doe",
                    "age": 30
                  }`}
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
                AssertionError: expected true to be false at Context.it (/test/test_parse.js:6:12) at callFn
                (/node_modules/mocha/mocha.js:5280:21) at hook (_node_modules/mocha/mocha.js:5333:10) at
                process._tickCallback (internal/process/next_tick.js:68:7)
              </pre>
            </CardContent>
          </Card>
        </div>
      </CardContent>
    </Card>
  )
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
  )
}
