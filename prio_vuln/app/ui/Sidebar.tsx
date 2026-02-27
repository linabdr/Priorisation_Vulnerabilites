'use client' //permet de faire le rendu côté client

import { Slider } from './components/Slider';

interface FilterState {
    search: string,
    minScore: number,
    maxScore: number,
    sortBy: string,
    sortOrder: 'asc' | 'desc'
}

interface SidebarProps {
    filters: FilterState,
    setFilters: React.Dispatch<React.SetStateAction<FilterState>>
}

export function Sidebar({ filters, setFilters }: SidebarProps) {

    return (
        <aside className="w-80 bg-gray-50 border-r border-gray-200 h-screen flex flex-col fixed left-0 top-0 overflow-y-auto">
            {/* Header */}
            <div className="p-6 border-b border-gray-200 bg-white sticky top-0 z-10">
                <div className="flex items-stretch gap-2 mb-1">
                    <h1 className="text-lg font-bold text--900 tracking-tight">Vulnerabilites Priorisation</h1>
                </div>
                <p className="text-xs text-gray-500">IoT Vulnerability Intelligence Platform</p>
            </div>
        </aside>
    );
}
