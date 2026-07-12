import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "William / Jarvis Dashboard | Digital Promotix",
    template: "%s | William / Jarvis Dashboard",
  },
  description:
    "William / Jarvis Multi-Agent AI SaaS Dashboard by Digital Promotix for agent control, security, memory, workflow automation, analytics, and workspace operations.",
  applicationName: "William / Jarvis Dashboard",
  authors: [{ name: "Digital Promotix" }],
  creator: "Digital Promotix",
  publisher: "Digital Promotix",
  robots: {
    index: false,
    follow: false,
  },
  icons: {
    icon: "/favicon.ico",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  themeColor: "#f2f2f0",
  colorScheme: "light",
};

type RootLayoutProps = {
  children: React.ReactNode;
};

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen overflow-x-hidden bg-[#f2f2f0] text-zinc-950 antialiased">
        {children}
      </body>
    </html>
  );
}
