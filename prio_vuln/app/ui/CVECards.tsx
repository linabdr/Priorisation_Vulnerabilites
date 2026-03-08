'use client'
import { ShieldAlert, Activity, BarChart3, Calendar } from 'lucide-react';
import { motion } from 'motion/react';


interface CVE {
    id: number,
    cve_id: string,
    description: string,
    cvss_score: number,
    epss_score: number,
    kev_status: boolean,
    severity: string,
    published_date: number,
    priority_score: number,
    type_vulnerabilite: string
}

interface CVECardsProps{
    cve: CVE;
}

export default function CVECards({cve}: CVECardsProps){
    const getSeverity = (score: number) => {
        if(score >= 9.0) return 'text-red-700 bg-red-70 border-red-250'; //severité élevée == rouge
        if(score >= 7.0) return 'text-orange-700 bg-orange-70 border-orange-250'; //severité moyenne == orange
        if(score >= 4.0) return 'text-yellow-700 bg-yellow-70 border-yellow-250'; //severité faible == jaune
    }
    return (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.01]">

            <div className="flex justify-between items-start mb-4">
                <h3 className="text-xl font-bold text-gray-900 font-mono tracking-tight">
                    {cve.cve_id}
                </h3>
                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${getSeverity(cve.cvss_score)}`}>
                    {cve.severity}
                </span>
            </div>

            <p className="text-gray-600 text-sm leading-relaxed mb-6">
                {cve.description}
            </p>

            <div className="grid grid-cols-3 gap-4 border-t border-gray-100 pt-4">
                <ScoreMetric label="Score CVSS" value={cve.cvss_score} icon={<ShieldAlert size={16} />} />
                <ScoreMetric label="Score EPPS" value={cve.epss_score} icon={<Activity size={16} />} />
                <div className="flex flex-col">
                    <div className="flex items-center gap-1.5 text-gray-500 mb-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider">Status KEV</span>
                    </div>
                    {cve.kev_status ? (<span className="text-lg font-mono font-semibold text-red-900"> Faille exploitée</span>) : (<span className="text-lg font-mono font-semibold text-gray-900"> Faille non exploitée</span>)}
                </div>
            </div>

            <div className="mt-4 pt-4 border-t border-gray-100 flex items-center text-xs text-gray-400">
                <Calendar size={14} className="mr-2" />
                Published: {cve.published_date}
            </div>
        </div>
    );
}
function ScoreMetric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
    return (
        <div className="flex flex-col">
        <div className="flex items-center gap-1.5 text-gray-500 mb-1">
        {icon}
        <span className="text-[10px] font-bold uppercase tracking-wider">{label}</span>
        </div>
        <span className="text-lg font-mono font-semibold text-gray-900">{value}</span>
        </div>
    );
}
