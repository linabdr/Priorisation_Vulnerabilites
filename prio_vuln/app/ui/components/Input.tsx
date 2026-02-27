interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
}

export function Input({ label, className, ...props }: InputProps) {
    return (
        <div className={`flex flex-col gap-1.5 ${className}`}>
        {label && (
            <label className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            {label}
            </label>
        )}
        <input
        className="px-3 py-2 bg-white border border-gray-300 rounded-lg text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-shadow"
        {...props}
        />
        </div>
    );
}
