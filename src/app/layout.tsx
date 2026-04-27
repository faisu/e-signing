import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'DSC e-Signing',
  description: 'PAdES-compliant digital signature with Indian Class 3 DSC tokens',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 text-gray-900 antialiased">
        {children}
      </body>
    </html>
  );
}
