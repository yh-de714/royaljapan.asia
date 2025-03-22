'use client'
import React from 'react';
import Order from "@/app/order/testcomp";

const Page = ({searchParams}) => {
    console.log(searchParams)

    return (
        <div>
            <Order searchParams={searchParams}/>
        </div>
    );
};

export default Page;