'use client'
import { ShieldAlert, Activity, BarChart3, Calendar, ClockAlert, Bug, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { fetchRecommendation } from '../actions';


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

interface recommandation {
    type_vulnerabilite: string,
    scenario_attaque: string,
    corrective: string,
    reduction_exposition: string,
    reduction_impact: string
}

export default function CVECards({cve}: CVECardsProps){
    const [isExpanded, setIsExpanded] = useState(false);
    const [recommendation, setRecommendation] = useState<Recommendation | null>(null);
    const [loading, setLoading] = useState(false);


    const getSeverity = (score: number) => {
        if(score >= 9.0) return 'text-red-700 bg-red-70 border-red-250'; //severité élevée == rouge
        if(score >= 7.0) return 'text-orange-700 bg-orange-70 border-orange-250'; //severité moyenne == orange
        if(score >= 4.0) return 'text-yellow-700 bg-yellow-70 border-yellow-250'; //severité faible == jaune
    }

    const handleToggleRecommendation = async () => {
        if (!isExpanded && !recommendation) {
            // Charge les recommandations seulement si pas encore chargées
            setLoading(true);
            try {
                const data = await fetchRecommendation(cve.type_vulnerabilite);
                setRecommendation(data);
            } catch (error) {
                console.error('Erreur lors du chargement des recommandations:', error);
            } finally {
                setLoading(false);
            }
        }
        setIsExpanded(!isExpanded);
    };


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

            <div className="grid grid-cols-5 gap-6 border-t border-gray-100 pt-4">
                <ScoreMetric label="Score CVSS" value={cve.cvss_score} icon={<ShieldAlert size={16} />} />
                <ScoreMetric label="Score EPPS" value={cve.epss_score} icon={<Activity size={16} />} />
                <ScoreMetric label="Score de priorité" value={cve.priority_score.toFixed(3)} icon={<ClockAlert size={16}/>}/>
                <ScoreMetric label="Type de vulnérabilité" value={formatVulnType(cve.type_vulnerabilite)} icon={<Bug size={16}/>}/>
                <div className="flex flex-col">
                    <div className="flex items-center gap-1.5 text-gray-500 mb-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider">Status KEV</span>
                    </div>
                    {cve.kev_status ? (<span className="text-lg font-mono font-semibold text-red-900"> Faille exploitée</span>) : (<span className="text-lg font-mono font-semibold text-gray-900"> Faille non exploitée</span>)}
                </div>
            </div>
            <div className="grid grid-cols-2 gap-8 mt-4 pt-4 border-t border-gray-100 flex items-center text-xs text-gray-400">
                <div className="flex flex-col">
                    <div className="flex items-center gap-1.5 text-gray-400">
                    <Calendar size={14} className="mr-2" />
                    <span>Published: {cve.published_date} </span>
                    </div>
                </div>

                <div className="flex justify-end">
                    <button
                        onClick={handleToggleRecommendation}
                        className="flex items-center gap-2 px-4 py-2 text-indigo-700 rounded-lg text-sm font-medium ">
                        Recommandations
                        <ChevronDown
                            size={16}
                            className={`transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        />
                    </button>
                </div>
            </div>

            {isExpanded && (
                <div className="mt-4 pt-4 border-t border-gray-200 bg-indigo-50/50 rounded-lg p-4 animate-in slide-in-from-top duration-200">
                {loading ? (
                    <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
                    </div>
                ) : recommendation ? (
                    <div className="space-y-4">
                    <div className="flex items-center gap-2 text-indigo-900 font-semibold">
                    <h4 className="text-lg">Recommandations pour les</h4>
                    <h4 className="text-lg lowercase">{formatVulnType(cve.type_vulnerabilite)}</h4>
                    </div>

                    {recommendation.scenario_attaque && (
                        <div>
                        <h5 className="text-sm font-bold text-gray-700 mb-2">Scénario d'attaque:</h5>
                        <p className="text-sm text-gray-600 leading-relaxed">
                        {recommendation.scenario_attaque}
                        </p>
                        </div>
                    )}

                    {recommendation.corrective && (
                        <div>
                        <h5 className="text-sm font-bold text-gray-700 mb-2">Correctif proposé:</h5>
                        <p className="text-sm text-gray-600 leading-relaxed">
                        {recommendation.corrective}
                        </p>
                        </div>
                    )}

                    {recommendation.reduction_exposition && (
                        <div>
                        <h5 className="text-sm font-bold text-gray-700 mb-2">Moyen de réduction de l'exposition :</h5>
                        <p className="text-sm text-gray-600 leading-relaxed">
                        {recommendation.reduction_exposition}
                        </p>
                        </div>
                    )}

                    {recommendation.reduction_impact && (
                        <div>
                        <h5 className="text-sm font-bold text-gray-700 mb-2">Moyen de réduction de l'impact :</h5>
                        <p className="text-sm text-gray-600 leading-relaxed">
                        {recommendation.reduction_impact}
                        </p>
                        </div>
                    )}

                    </div>
                ) : (
                    <div className="text-center py-4 text-gray-500">
                    <p>Aucune recommandation disponible pour ce type de vulnérabilité.</p>
                    </div>
                )}
                </div>
            )}

        </div>
    );
}
function ScoreMetric({ label, value, icon }: { label: string; value: any; icon: React.ReactNode }) {
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

function formatVulnType(type_vulnerabilite: string){
    if(type_vulnerabilite==="injection"){
        return "Injection"
    }
    if(type_vulnerabilite==="auth_bypass"){
        return "Authentification bypass"
    }
    if(type_vulnerabilite==="buffer_overflow"){
        return "Buffer overflow"
    }
    if(type_vulnerabilite==="autre"){
        return "Autre type de vulnérabilité"
    }
    if(type_vulnerabilite===""){
        return "Erreur !"
    }
}
