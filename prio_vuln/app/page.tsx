import Sidebar from "./ui/Sidebar"
import CVECards from "./ui/CVECards"
import getCVEs from "./db"

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

export default async function Page(
  { searchParams }:{searchParams: Promise<{ [key: string]: string | string[] | undefined}>;}
){
  const params = await searchParams;
  const filters = {
    search: (params.search as string) || '',
    minScore: params.minScore ? parseFloat(params.minScore as string) : undefined,
    maxScore: params.maxScore ? parseFloat(params.maxScore as string) : undefined,
    sortBy: (params.sortBy as string) || 'published_date',
    sortOrder: (params.sortOrder as 'asc' | 'desc') || 'desc',
  };
  const cves = await getCVEs(filters);
  return(
    <div className="min-h-screen bg-gray-100 font-sans text-gray-900 flex">
      <Sidebar/>
          <main className="flex-1 p-8 ml-80">
              <header className="mb-8 flex justify-between items-end">
                  <div>
                      <h2 className="text-3xl font-bold text-gray-900 tracking-tight">Vulnerability Database</h2>
                      <p className="text-gray-500 mt-2">Showing {cves.length} results based on current filters</p>
                  </div>
                  <div className="text-sm text-gray-400 font-mono">
                      Last updated: {new Date().toLocaleDateString()}
                  </div>
              </header>

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                  {cves.map((cve: any) => (
                      <CVECards key={cve.id} cve={cve} />
                  ))}

                  {cves.length === 0 && (
                      <div className="col-span-full flex flex-col items-center justify-center h-64 text-gray-400 border-2 border-dashed border-gray-200 rounded-xl">
                          <p>No CVEs found matching your criteria.</p>
                      </div>
                  )}
              </div>
          </main>

    </div>

  )
}
