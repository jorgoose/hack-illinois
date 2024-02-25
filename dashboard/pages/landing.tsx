import Link from 'next/link';
import { Button } from '@/components/ui/button';

export default function LandingPage() {
    return (
        <div className="flex flex-col min-h-screen bg-gradient-to-r from-gray-700 via-gray-900 to-black text-white">
          <main className="flex flex-1 flex-col p-4 md:p-10">
            <div className="max-w-6xl w-full mx-auto grid gap-2">
              <div className="text-center mb-10 pt-32">
                <div className="flex justify-center mb-8">
                  <ShieldIcon className="w-20 h-20 text-cyan-500" />
                  <h1 className="text-7xl font-bold ml-4">Fuzz<span className="text-cyan-500">Guard</span></h1>
                </div>
                <p className="text-2xl">
                    Automated and scalable fuzz testing for your repositories to detect potential vulnerabilities.
                </p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div className="bg-gray-800 shadow-xl rounded-lg p-6">
                  <GithubIcon className="w-12 h-12 text-gray-400" />
                  <h2 className="mt-4 text-xl font-semibold">Log in with GitHub</h2>
                  <p className="mt-2 text-gray-400">
                    Easily authenticate and link your GitHub account.
                  </p>
                </div>
                <div className="bg-gray-800 shadow-xl rounded-lg p-6">
                  <CheckCircleIcon className="w-12 h-12 text-green-500" />
                  <h2 className="mt-4 text-xl font-semibold">View and Select a Repository</h2>
                  <p className="mt-2 text-gray-400">
                    Browse and select any of your repositories for automated fuzz testing.
                  </p>
                </div>
                <div className="bg-gray-800 shadow-xl rounded-lg p-6">
                  <CoffeeIcon className="w-12 h-12 text-yellow-500"/>
                  <h2 className="mt-4 text-xl font-semibold">Sit Back and Relax</h2>
                  <p className="mt-2 text-gray-400">
                    We perform automated fuzz testing while you focus on other tasks.
                  </p>
                </div>
                <div className="bg-gray-800 shadow-xl rounded-lg p-6">
                  <ShieldIcon className="w-12 h-12 text-cyan-500" />
                  <h2 className="mt-4 text-xl font-semibold">View Analytics and Reporting</h2>
                  <p className="mt-2 text-gray-400">
                    Access detailed analytics and reports once the testing is complete.
                  </p>
                </div>
              </div>
              <div className="text-center">
                <Link href="/">
                  <Button className="bg-cyan-500 hover:bg-cyan-600 text-white py-8 px-12 rounded-lg text-xl font-semibold shadow-lg">
                    Get Started
                  </Button>
                </Link>
                <Link href="/">
                  <Button className="ml-4 bg-transparent hover:bg-gray-700 text-white py-8 px-12 rounded-lg text-xl font-semibold border border-gray-500 hover:border-transparent shadow-lg">
                    Learn More
                  </Button>
                </Link>
              </div>
            </div>
          </main>
        </div>
    );
}


interface IconProps {
    className?: string;
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

function GithubIcon(props: IconProps) {
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

// Circle with check in the middle
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
        <circle cx="12" cy="12" r="10" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    );
  }
  
  // Coffee cup icon
  function CoffeeIcon(props: IconProps) {
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
        <path d="M16 8h1a2 2 0 0 1 0 4h-1" />
        <path d="M2 8h12v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8z" />
        <path d="M6 1c0.5 1 0.5 2 0 3" />
        <path d="M10 1c0.5 1 0.5 2 0 3" />
      </svg>
    );
  }
  
  
  
  



