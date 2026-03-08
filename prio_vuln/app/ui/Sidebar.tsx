'use client' //permet de faire le rendu côté client

import { useRouter, useSearchParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { Search, Filter, ArrowUpDown } from 'lucide-react';
import { Input } from './components/Input';
import { Slider } from './components/Slider';
import { Checkbox } from './components/Checkbox';

interface FilterState {
    search: string,
    minScore: number,
    maxScore: number,
    sortBy: string,
    sortOrder: 'asc' | 'desc'
}

export default function Sidebar() {
    const router = useRouter();
    const searchParams = useSearchParams();

    const [filters, setFilters] = useState<FilterState>({
        search: searchParams.get('search') || '',
        minScore: parseFloat(searchParams.get('minScore') as string) || 0,
        maxScore: parseFloat(searchParams.get('maxScore') as string) || 10,
        sortBy: searchParams.get('sortBy') || 'published_date',
        sortOrder: (searchParams.get('sortorder') as 'asc' | 'desc') || 'desc'
    });

    useEffect(() => {
        const params = new URLSearchParams();
        if (filters.search) params.set('search', filters.search);
        params.set('minScore', filters.minScore.toString());
        params.set('maxScore', filters.maxScore.toString());
        params.set('sortBy', filters.sortBy);
        params.set('sortOrder', filters.sortOrder);

        //debouncing: on attend qu'il n'y ai plus d'action utilisation pdt 300ms ==> s'assurer que les filtres sont fini de selectionner
        const timeoutId = setTimeout(() => {
            router.push(`/?${params.toString()}`);
        }, 300);

        return () => clearTimeout(timeoutId);

    }, [filters, router]);

    // --------------- HANDLER

    // CVSS SCORE
    const handleMinScoreChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFilters(prev => ({ ...prev, minScore: parseFloat(e.target.value) }));
    };
    const handleMaxScoreChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFilters(prev => ({ ...prev, maxScore: parseFloat(e.target.value) }));
    };

    // SEARCH
    const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFilters(prev => ({ ...prev, search: e.target.value }));
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
            {/* --FILTRE-- */}
            <div className="p-6 space-y-8 flex-1">

                {/* Search */}
                <section>
                    <Input
                        label='Rechercher des CVE'
                        placeholder=''
                        value={filters.search}
                        onChange={handleSearchChange}
                    />
                </section>

                {/* Score CVSS */}
                <section className="space-y-4">
                    <div className="flex items-center gap-2 text-gray-900 font-medium text-sm">
                        <Filter size={16} />
                        <span>Score CVSS</span>
                    </div>
                    <div className="p-4 bg-white rounded-xl border border-gray-200 shadow-sm space-y-4">
                        <Slider
                        label="Maximum Score"
                        value={filters.maxScore}
                        min={0}
                        max={10}
                        onChange={handleMaxScoreChange}
                        />
                        <Slider
                            label="Minimum Score"
                            value={filters.minScore}
                            min={0}
                            max={10}
                            onChange={handleMinScoreChange}
                        />
                    </div>
                </section>

                {/* Checkbox */}
                <section className="space-y-4 pt-4 border-t border-gray-200">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Other Filters</h3>
                <div className="space-y-2">
                <Checkbox label="N'afficher que les vulnérabilités exploitées" checked={false} onChange={() => {}} />
                </div>
                </section>
                {/* Trie */}
                <section>
                </section>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-gray-200 text-xs text-gray-400 text-center">
            Projet du cours de cybersécurité dans l'IoT
            <p>Lina Bader - Maxime Bintein - Oum el kheir Righi</p>
            </div>

        </aside>
    );
}
