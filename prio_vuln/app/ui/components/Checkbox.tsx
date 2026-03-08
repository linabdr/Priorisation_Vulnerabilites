import React from 'react';
import { Check } from 'lucide-react';

interface CheckboxProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label: string;
}

export function Checkbox({ label, checked, onChange, className, ...props }: CheckboxProps) {
    return (
        <label className={`flex items-center gap-3 cursor-pointer group ${className}`}>
                <div className={`relative flex items-center justify-center w-5 h-5 border rounded transition-colors ${checked ? 'bg-indigo-600 border-indigo-600' : 'bg-white border-gray-300 group-hover:border-indigo-500'}`}>
                    <input
                    type="checkbox"
                    className="sr-only"
                    checked={checked}
                    onChange={onChange}
                    {...props}
                    />
                {checked && <Check size={14} className="text-white" strokeWidth={3} />}
            </div>
            <span className="text-xs text-gray-700 group-hover:text-gray-900">{label}</span>
        </label>
    );
}
