interface SliderProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string,
    value: number,
    min?: number,
    max?: number,
    step?: number,
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

export function Slider({ label, value, min = 0, max = 10, step = 0.1, onChange, className, ...props }: SliderProps) {
    return (
        <div className={`flex flex-col gap-2 ${className}`}>
        {label && (
            <div className="flex justify-between">
            <label className="text-xs font-medium text-gray-500 uppercase tracking-wider">{label}</label>
            <span className="text-xs font-mono text-gray-900">{value}</span>
            </div>
        )}
        <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={onChange}
        className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
        {...props}
        />
        </div>
    );
}
