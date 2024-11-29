import React from 'react';
import { LucideIcon } from 'lucide-react';

interface IconWithTitleProps {
  icon: LucideIcon;
  title: string;
  className?: string;
}

export default function IconWithTitle({ icon: Icon, title, className = "w-5 h-5" }: IconWithTitleProps) {
  return (
    <div className="relative inline-block" title={title}>
      <Icon className={className} aria-hidden="true" />
      <span className="sr-only">{title}</span>
    </div>
  );
}