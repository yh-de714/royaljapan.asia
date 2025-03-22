"use client";
import React, { Suspense, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

// export const metadata = {
//     title: 'test',
//     description: 'Something',
// }

const Layout = ({ children }) => {
  const [userData, setUserData] = useState(null);

  useEffect(() => {
    let parsedUserData =
      JSON.parse(window.localStorage?.getItem("userData")) || null;

    if (parsedUserData) setUserData(parsedUserData);
  }, []);

  const router = useRouter();

  useEffect(() => {
    if (userData) router.push("/dashboard");
  }, []);

  return (
    <div>
      <Suspense>{children}</Suspense>
    </div>
  );
};

export default Layout;
