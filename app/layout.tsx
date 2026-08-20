import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://localhost:8443"),
  title: "CyberTarcza Local",
  description: "Lokalne, szyfrowane centrum ochrony Windowsa, Androida, routera i kont.",
  openGraph: { title: "CyberTarcza Local", description: "Lokalnie. Szyfrowane. Pod Twoją kontrolą.", images: ["/og.png"] },
  twitter: { card: "summary_large_image", title: "CyberTarcza Local", description: "Lokalnie. Szyfrowane. Pod Twoją kontrolą.", images: ["/og.png"] },
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pl"><body>{children}</body></html>;
}
