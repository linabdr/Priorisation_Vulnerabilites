'use client' //permet de faire le rendu côté client

import { Slider } from './components/Slider';
import { Search, Filter, ArrowUpDown } from 'lucide-react';

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


    const handleMinScoreChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFilters(prev => ({ ...prev, minScore: parseFloat(e.target.value) }));
    };
    const handleMaxScoreChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFilters(prev => ({ ...prev, maxScore: parseFloat(e.target.value) }));
    };

    return (
        <aside className="w-80 bg-gray-50 border-r border-gray-200 h-screen flex flex-col fixed left-0 top-0 overflow-y-auto">
            {/* Header */}
            <div className="p-6 border-b border-gray-200 bg-white sticky top-0 z-10">
                <div className="flex items-stretch gap-2 mb-1">
                    <h1 className="text-lg font-bold text--900 tracking-tight">Vulnerabilites Priorisation</h1>
                </div>
                <p className="text-xs text-gray-500">IoT Vulnerability Intelligence Platform</p>
            </div>

            <div className="p-6 space-y-8 flex-1">
                {/* Score Range */}
                <section className="space-y-4">
                    <div className="flex items-center gap-2 text-gray-900 font-medium text-sm">
                        <Filter size={16} />
                        <span>Score CVSS</span>
                    </div>
                    <div className="p-4 bg-white rounded-xl border border-gray-200 shadow-sm space-y-4">
                        <Slider
                            label="Minimum Score"
                            value={filters.minScore}
                            min={0}
                            max={10}
                            onChange={handleMinScoreChange}
                        />
                        <Slider
                            label="Maximum Score"
                            value={filters.maxScore}
                            min={0}
                            max={10}
                            onChange={handleMaxScoreChange}
                        />
                    </div>
                </section>
            </div>
        </aside>
    );
}
