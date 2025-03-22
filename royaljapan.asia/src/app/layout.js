import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import localFont from 'next/font/local';

// const geistSans = Geist({
//   variable: "--font-geist-sans",
//   subsets: ["latin"],
// });
//
// const geistMono = Geist_Mono({
//   variable: "--font-geist-mono",
//   subsets: ["latin"],
// });


// const myFont = localFont({
//   src: [
//     {
//       path: '/public/assets/fonts/Gotham Book.otf',
//       // weight: '400',
//       // style: 'normal',
//     },
//   ],
//   display: 'swap', // Recommended for performance
// });



export const metadata = {
  title: '商品 | ロイヤルジャパン公式通販サイト',
  description: 'Something',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <link rel="icon" href="/favicon.svg" sizes="any" />

      <body
          // className={`${geistSans.variable} ${geistMono.variable}`}
      >
        {children}
      </body>
    </html>
  );
}
