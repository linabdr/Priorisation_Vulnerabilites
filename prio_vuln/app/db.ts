import Database from 'better-sqlite3';

const db = new Database("./public/vulnerabilities.db");

const count = db.prepare('SELECT count(*) as count FROM vulnerabilities').get() as { count: number };
if(count.count === 0) {
    console.log("erreur: la bdd est vide");
}

export default async function getCVEs(filters: any){
    let query = "SELECT * FROM vulnerabilities WHERE 1=1";
    const params: any[]=[];

    // Bar de recherche = ajout mots dans le requete sql qui cherche correspondance dans description ou cve_id
    if (filters.search) {
        query += ' AND (cve_id LIKE ? OR description LIKE ?)';
        params.push(`%${filters.search}%`, `%${filters.search}%`);
    }

    // Filtre du score CVSS
    if (filters.minScore) {
        query += ' AND cvss_score >= ?';
        params.push(filters.minScore);
    }

    if (filters.maxScore) {
        query += ' AND cvss_score <= ?';
        params.push(filters.maxScore);
    }

    // Filtrage
    if (filters.sortBy) {
        const validSorts = ['cvss_score', 'epss_score', 'kev_status', 'published_date'];
        if (validSorts.includes(filters.sortBy)) {
            query += ` ORDER BY ${filters.sortBy} ${filters.sortOrder === 'asc' ? 'ASC' : 'DESC'}`;
        }
    } else {
        query += ' ORDER BY id DESC';
    }

    return db.prepare(query).all(...params);
}
