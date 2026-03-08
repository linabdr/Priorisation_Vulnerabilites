import Database from 'better-sqlite3';

const db = new Database("./public/vulnerabilities.db");

const count = db.prepare('SELECT count(*) as count FROM vulnerabilities').get() as { count: number };
if(count.count === 0) {
    console.log("erreur: la bdd est vide");
}

// Récup CVE dans table vulnerabilities
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

    if (filters.severity && filters.severity.length > 0 && filters.severity.length < 4) {
        const placeholders = filters.severity.map(() => '?').join(',');
        query += ` AND severity IN (${placeholders})`;
        params.push(...filters.severity);
    }

    // Select Vuln type
    if (filters.typeVuln) {
        query += ' AND type_vulnerabilite = ?';
        params.push(filters.typeVuln);
    }

    // Tri
    if (filters.sortBy) {
        const validSorts = ['cvss_score', 'epss_score', 'priority_score', 'published_date'];
        if (validSorts.includes(filters.sortBy)) {
            query += ` ORDER BY ${filters.sortBy} ${filters.sortOrder === 'asc' ? 'ASC' : 'DESC'}`;
        }
    } else {
        query += ' ORDER BY id DESC';
    }

    // Calc nombre de CVE avec filtres
    const countQuery = 'SELECT COUNT(*) as total FROM vulnerabilities WHERE 1=1' + query.substring(query.indexOf('WHERE 1=1')+9).split('ORDER BY')[0];

    const totalResult = db.prepare(countQuery).get(...params) as { total: number};
    const total = totalResult.total;

    // Pagination
    const page = filters.page || 1;
    const limit = filters.limit || 20;
    const offset = (page - 1)*limit;

    query += ' LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const res = db.prepare(query).all(...params);

    return {
        data: res,
        pagination: {
            page,
            limit,
            total,
            totalPage: Math.ceil(total / limit)
        }
    };
}

// Récup les recommandation dans la table recommandation
export async function getRecommendation(typeVuln: string) {
    const query = `
    SELECT * FROM recommandations
    WHERE type_vulnerabilite = ?
    LIMIT 1
    `;

    const result = db.prepare(query).get(typeVuln);
    return result as any;
}
