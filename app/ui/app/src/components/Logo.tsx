export default function Logo() {
  return (
    <div className="flex flex-col mb-8 items-center justify-center select-none">
      <div className="relative select-none group">
        <svg
          width="80"
          height="80"
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="select-none drop-shadow-sm transition-transform duration-500 group-hover:rotate-12"
        >
          {/* Outer glow effect (simulated with multiple circles) */}
          <circle cx="12" cy="12" r="10" fill="currentColor" className="text-primary/5" />
          <circle cx="12" cy="12" r="8" fill="currentColor" className="text-primary/10" />

          {/* The Moon */}
          <path
            d="M12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22C17.5228 22 22 17.5228 22 12C22 11.4373 21.9535 10.8855 21.8638 10.349C20.6548 11.3789 19.1001 12 17.4 12C13.3681 12 10.1 8.73188 10.1 4.7C10.1 3.6339 10.3292 2.62128 10.7428 1.70886C10.3541 1.63604 9.95427 1.6 9.55 1.6L12 2Z"
            fill="currentColor"
            className="text-primary"
          />

          {/* Small crater details */}
          <circle cx="8" cy="14" r="1.5" fill="currentColor" className="text-primary-foreground/20" />
          <circle cx="14" cy="18" r="1" fill="currentColor" className="text-primary-foreground/20" />
          <circle cx="6" cy="10" r="0.8" fill="currentColor" className="text-primary-foreground/20" />
        </svg>
      </div>
      <h2 className="mt-4 text-3xl font-bold font-rounded tracking-tight text-neutral-900 dark:text-white">
        Luna AI
      </h2>
      <p className="mt-2 text-neutral-500 dark:text-neutral-400 font-medium">
        How can I help you today?
      </p>
    </div>
  );
}
