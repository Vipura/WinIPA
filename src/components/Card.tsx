// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React from "react";
import { LucideIcon, ArrowRight, Lock } from "lucide-react";

interface ActionCardProps {
  title: string;
  description: string;
  icon: LucideIcon;
  badge?: string;
  disabled?: boolean;
  actionText: string;
  onClick?: () => void;
}

export const ActionCard: React.FC<ActionCardProps> = ({
  title,
  description,
  icon: Icon,
  badge,
  disabled = false,
  actionText,
  onClick,
}) => {
  return (
    <div
      className={`action-card ${disabled ? "card-disabled" : "card-interactive"}`}
      onClick={!disabled ? onClick : undefined}
      role={!disabled ? "button" : undefined}
      tabIndex={!disabled ? 0 : -1}
      onKeyDown={(e) => {
        if (!disabled && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          onClick?.();
        }
      }}
    >
      <div className="card-top">
        <div className={`card-icon-wrapper ${disabled ? "icon-disabled" : ""}`}>
          <Icon size={24} />
        </div>
        {badge && (
          <span className={`card-badge ${disabled ? "badge-disabled" : "badge-active"}`}>
            {disabled && <Lock size={12} style={{ marginRight: 4, display: "inline" }} />}
            {badge}
          </span>
        )}
      </div>

      <div className="card-body">
        <h3 className="card-title">{title}</h3>
        <p className="card-description">{description}</p>
      </div>

      <div className="card-footer">
        <span className="card-action-text">{actionText}</span>
        {!disabled ? <ArrowRight size={16} /> : null}
      </div>
    </div>
  );
};
