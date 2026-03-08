'use server'

import { getRecommendation } from './db'

export async function fetchRecommendation(typeVuln: string) {
    return await getRecommendation(typeVuln);
}
