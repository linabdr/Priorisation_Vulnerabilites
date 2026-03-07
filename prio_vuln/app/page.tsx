'use client'
import { Sidebar } from "./ui/Sidebar"

import { useState, useEffect } from 'react';


export default function Page(){
  const [filters, setFilters] = useState({
    search: '',
    minScore: 0,
    maxScore: 10,
    sortBy: 'published_date',
    sortOrder: 'desc' as 'asc' | 'desc'
  });
  return(
    <div className="min-h-screen bg-gray-100 font-sans text-gray-900 flex">
      <Sidebar filters={filters} setFilters={setFilters} />
    </div>
  )
}
