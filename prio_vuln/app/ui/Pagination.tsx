'use client'

import { useSearchParams, usePathname, useRouter } from 'next/navigation'
import { MoveRight, MoveLeft } from 'lucide-react';

interface PaginationProps {
    currentPage: number
    totalPages: number
    total: number
}

export default function Pagination({ currentPage, totalPages, total }: PaginationProps) {
    const searchParams = useSearchParams()
    const pathname = usePathname()
    const router = useRouter()

    // Préparation de la page
    const createPageUrl = (pageNumber: number) => {
        const params = new URLSearchParams(searchParams);
        params.set("page", pageNumber.toString());
        return `${pathname}?${params.toString()}`
    }

    // Navigation vers la page
    const goToPage = (pageNumber: number) => {
        router.push(createPageUrl(pageNumber))
    }

    // Calcul des numéros des pages
    const getPageNumbers = () => {
        const pages = [];
        const showPages = 5;

        let start = Math.max(1, currentPage - Math.floor(showPages/2));
        let end = Math.min(totalPages, start + showPages - 1);

        // ajustement si proche de la fin
        if (end - start < showPages - 1) {
            start = Math.max(1, end - showPages + 1);
        }

        for (let i = start; i <= end; i++) {
            pages.push(i);
        }

        return pages
    }

    if (totalPages <= 1) return null;

    return (
        <div className="mt-8 flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3 sm:px-6 rounded-lg shadow">
            <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                <div>
                    <p className="text-sm text-gray-700">
                        Affichage de{' '}
                        <span className="font-medium">{(currentPage - 1) * 20 + 1}</span>
                        {' '}-{' '}
                        <span className="font-medium">
                            {Math.min(currentPage * 20, total)}
                        </span>
                        {' '}sur{' '}
                        <span className="font-medium">{total}</span> résultats
                    </p>
                </div>
                <div>
                    <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">

                    {/* Bouton Précédent */}
                    <button
                    onClick={() => goToPage(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                    <span className="sr-only">Previous</span>
                    <MoveLeft />
                    </button>

                    {/* Première page */}
                    {getPageNumbers()[0] > 1 && (
                        <>
                        <button
                        onClick={() => goToPage(1)}
                        className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"
                        >
                        1
                        </button>
                        {getPageNumbers()[0] > 2 && (
                            <span className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300">
                            ...
                            </span>
                        )}
                        </>
                    )}

                    {/* Numéros de pages */}
                    {getPageNumbers().map((pageNum) => (
                        <button
                        key={pageNum}
                        onClick={() => goToPage(pageNum)}
                        className={`relative inline-flex items-center px-4 py-2 text-sm font-semibold ring-1 ring-inset ring-gray-300 focus:z-20 focus:outline-offset-0 ${
                            pageNum === currentPage
                            ? 'z-10 bg-blue-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600'
                            : 'text-gray-900 hover:bg-gray-50'
                        }`}
                        >
                        {pageNum}
                        </button>
                    ))}

                    {/* Dernière page */}
                    {getPageNumbers()[getPageNumbers().length - 1] < totalPages && (
                        <>
                        {getPageNumbers()[getPageNumbers().length - 1] < totalPages - 1 && (
                            <span className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300">
                            ...
                            </span>
                        )}
                        <button
                        onClick={() => goToPage(totalPages)}
                        className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"
                        >
                        {totalPages}
                        </button>
                        </>
                    )}

                    {/* Bouton Suivant */}
                    <button
                    onClick={() => goToPage(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                    <span className="sr-only">Next</span>
                    <MoveRight />
                    </button>
                    </nav>
                </div>
            </div>
        </div>
    )
}


