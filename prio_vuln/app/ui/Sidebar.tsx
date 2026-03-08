'use client' //permet de faire le rendu côté client

import { useRouter, useSearchParams } from 'next/navigation';
import { useState, useEffect } from 'react';
import { Search, Filter, ArrowUpDown } from 'lucide-react';
import { Input } from './components/Input';
import { Slider } from './components/Slider';
import { Checkbox } from './components/Checkbox';

//FILTES
interface FilterState {
    search: string,
    minScore: number,
    maxScore: number,
    sortBy: string,
    sortOrder: 'asc' | 'desc',
    doesUse: boolean,
    severity: string[],
    typeVuln: string
}

export default function Sidebar() {
    const router = useRouter();
    const searchParams = useSearchParams();

    //FILTRES
    const [filters, setFilters] = useState<FilterState>({
        search: searchParams.get('search') || '',
        minScore: parseFloat(searchParams.get('minScore') as string) || 0,
        maxScore: parseFloat(searchParams.get('maxScore') as string) || 10,
        sortBy: searchParams.get('sortBy') || 'published_date',
        sortOrder: (searchParams.get('sortorder') as 'asc' | 'desc') || 'desc',
        doesUse: false,
        severity: searchParams.get('severity')?.split(',') || ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        typeVuln: searchParams.get('typeVuln') || ''
    });

    useEffect(() => {
        const params = new URLSearchParams();
        if (filters.search) params.set('search', filters.search);
        params.set('minScore', filters.minScore.toString());
        params.set('maxScore', filters.maxScore.toString());
        params.set('sortBy', filters.sortBy);
        params.set('sortOrder', filters.sortOrder);
        params.set('doesUse', filters.doesUse.toString());
        if (filters.severity.length > 0 && filters.severity.length < 4) {
            params.set('severity', filters.severity.join(','));
        }
        if (filters.typeVuln) {
            params.set('typeVuln', filters.typeVuln);
        }

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

    // -- CHECKBOXs

    // doesUse === N'affiche que les CVE qui sont exploité en ce moment, KEV=1
    const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const checked = e.target.checked;
        setFilters(prev => ({ ...prev, doesUse: checked }));
        //fetchCVEs({ ...filters, doesUse: checked }); // Appeler la fonction pour effectuer la requête SQL
    };

    // TRI
    const handleSortChange = (field: string) => {
        setFilters(prev => ({...prev, sortBy: field, sortOrder: prev.sortBy === field && prev.sortOrder === 'asc' ? 'desc' : 'asc'}));
    }

    //SELECT VULN TYPe
    const handleTypeVulnChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
        setFilters(prev => ({ ...prev, typeVuln: e.target.value }));
    };

    // SEVERITE
    const handleSeverityChange = (severity: string, checked: boolean) => {
        setFilters(prev => {
            let updated: string[];
            if (checked) {
                // Ajoute la sévérité si cochée
                updated = [...prev.severity, severity];
            } else {
                // Retire la sévérité si décochée
                updated = prev.severity.filter(s => s !== severity);
            }

            // Si aucune cochée, garde au moins un tableau vide ou force toutes
            if (updated.length === 0) {
                updated = []; // Ou ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] si tu veux forcer au moins une
            }

            return { ...prev, severity: updated };
        });
    };


    return (
        <aside className="w-80 bg-gray-50 border-r border-gray-200 h-screen flex flex-col fixed left-0 top-0 overflow-y-auto">
            {/* Header */}
            <div className="p-4 border-b border-gray-200 bg-white sticky top-0 z-10">
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

                {/* Tri */}
                <section className="space-y-3">
                    <div className="flex items-center gap-2 text-gray-900 font-medium text-sm">
                        <ArrowUpDown size={16} />
                        <span>Trier par</span>
                    </div>
                    <div className="space-y-2">
                        <SortOption
                        label="Score CVSS"
                        active={filters.sortBy === 'cvss_score'}
                        order={filters.sortOrder}
                        onClick={() => handleSortChange('cvss_score')}
                        />
                        <SortOption
                        label="Score EPSS"
                        active={filters.sortBy === 'evss_score'}
                        order={filters.sortOrder}
                        onClick={() => handleSortChange('evss_score')}
                        />
                        <SortOption
                        label="Score de priorité"
                        active={filters.sortBy === 'priority_score'}
                        order={filters.sortOrder}
                        onClick={() => handleSortChange('priority_score')}
                        />
                        <SortOption
                        label="Date de parution"
                        active={filters.sortBy === 'published_date'}
                        order={filters.sortOrder}
                        onClick={() => handleSortChange('published_date')}
                        />
                    </div>
                </section>

                {/* Checkbox faille exploité */}
                <section className="space-y-4 pt-4 border-t border-gray-200">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">N'afficher que:</h3>
                <div className="space-y-2">
                <Checkbox
                    label="Les failles exploitées"
                    checked={filters.doesUse}
                    onChange={handleCheckboxChange} />
                </div>

                {/*Selecteur type vuln*/}
                <select
                    className="flex w-full px-3 py-2.5 text-heading text-xs border border-gray-200 rounded-md shadow-md placeholder:text-body"
                    placeholder={"Choisir un type de vulnérabilité"}
                    onChange={handleTypeVulnChange}
                >
                    <option value="">
                        Choisir un type de vulnérabilité
                    </option>
                    <option value="injection">Injection</option>
                    <option value="auth_bypass">Authentification bypass</option>
                    <option value="buffer_overflow">Buffer overflow</option>
                    <option value="autre">Autres</option>
                </select>

                {/* Checkbox pour Sévérité*/}
                <div className="flex items-center gap-2 text-gray-400 font-medium text-sm">
                    <span>Sévérité</span>
                </div>
                <div className="p-4 bg-white rounded-xl border border-gray-200 shadow-sm space-y-3">
                    <Checkbox
                    label="CRITICAL"
                    checked={filters.severity.includes('CRITICAL')}
                    onChange={(e) => handleSeverityChange('CRITICAL', e.target.checked)}
                    className="text-red-700"
                    />
                    <Checkbox
                    label="HIGH"
                    checked={filters.severity.includes('HIGH')}
                    onChange={(e) => handleSeverityChange('HIGH', e.target.checked)}
                    className="text-orange-700"
                    />
                    <Checkbox
                    label="MEDIUM"
                    checked={filters.severity.includes('MEDIUM')}
                    onChange={(e) => handleSeverityChange('MEDIUM', e.target.checked)}
                    className="text-yellow-700"
                    />
                    <Checkbox
                    label="LOW"
                    checked={filters.severity.includes('LOW')}
                    onChange={(e) => handleSeverityChange('LOW', e.target.checked)}
                    className="text-green-700"
                    />
                </div>
                </section>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-gray-200 text-xs text-gray-400 text-center">
            Projet du cours 8INF917
            <p>Lina Bader - Maxime Bintein - Oum el kheir Righi</p>
            </div>

        </aside>
    );
}

function SortOption({ label, active, order, onClick }: { label: string, active: boolean, order: 'asc' | 'desc', onClick: () => void }) {
    return (
        <button
        onClick={onClick}
        className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors ${
            active
            ? 'bg-indigo-50 text-indigo-700 font-medium'
            : 'text-gray-600 hover:bg-gray-100'
        }`}
        >
        <span>{label}</span>
        {active && (
            <span className="text-xs uppercase font-bold tracking-wider">
            {order === 'asc' ? 'Low → High' : 'High → Low'}
            </span>
        )}
        </button>
    );
}
