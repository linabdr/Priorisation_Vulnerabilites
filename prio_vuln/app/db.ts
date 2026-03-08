import Database from 'better-sqlite3';

const db = new Database("./public/vulnerabilities.db");

const count = db.prepare('SELECT count(*) as count FROM vulnerabilities').get() as { count: number };
if(count.count === 0) {
    console.log("erreur: la bdd est vide");
}

export default async function getCVEs(filters: any){
    let query = "SELECT cve_id as id, cve_id, description, cvss_score, severity, epss_score, kev_status, published_date, priority_score, type_vulnerabilite FROM vulnerabilities WHERE 1=1";
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

    // Checkbox
    if(filters.doesUse){
        query += ' AND kev_status = 1';
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

    console.log("Query générée:", query);
    console.log("Params:", params);

    return db.prepare(query).all(...params);
}
