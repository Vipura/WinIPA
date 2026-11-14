// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

import React from "react";
import { STRINGS } from "../strings";
import { ActionCard } from "../components/Card";
import { Package, DownloadCloud, Hammer, Smartphone } from "lucide-react";

interface HomeScreenProps {
  onNavigate: (view: "home" | "install" | "device-account") => void;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({ onNavigate }) => {
  return (
    <div className="home-screen">
      <div className="hero-section">
        <h2 className="hero-title">{STRINGS.home.welcome}</h2>
        <p className="hero-subtitle">{STRINGS.home.subtitle}</p>
      </div>

      <div className="cards-grid">
        {/* Card 1: Install IPA (Active in Phase 1) */}
        <ActionCard
          title={STRINGS.home.cards.installIpa.title}
          description={STRINGS.home.cards.installIpa.desc}
          icon={Package}
          badge={STRINGS.home.cards.installIpa.badge}
          actionText={STRINGS.home.cards.installIpa.action}
          onClick={() => onNavigate("install")}
        />

        {/* Card 2: From GitHub Release (Disabled with Coming Soon) */}
        <ActionCard
          title={STRINGS.home.cards.githubRelease.title}
          description={STRINGS.home.cards.githubRelease.desc}
          icon={DownloadCloud}
          badge={STRINGS.home.cards.githubRelease.badge}
          disabled={true}
          actionText={STRINGS.home.cards.githubRelease.action}
        />

        {/* Card 3: Build from repo/folder (Disabled with Coming Soon) */}
        <ActionCard
          title={STRINGS.home.cards.buildRepo.title}
          description={STRINGS.home.cards.buildRepo.desc}
          icon={Hammer}
          badge={STRINGS.home.cards.buildRepo.badge}
          disabled={true}
          actionText={STRINGS.home.cards.buildRepo.action}
        />

        {/* Card 4: Device & Account (Active in Phase 1) */}
        <ActionCard
          title={STRINGS.home.cards.deviceAccount.title}
          description={STRINGS.home.cards.deviceAccount.desc}
          icon={Smartphone}
          badge={STRINGS.home.cards.deviceAccount.badge}
          actionText={STRINGS.home.cards.deviceAccount.action}
          onClick={() => onNavigate("device-account")}
        />
      </div>

      <div className="ground-truth-banner">
        <span className="ground-truth-heading">Honest Disclosure:</span>
        <span>
          Free Apple IDs limit sideloaded apps to 7-day validity and 3 active apps at a time.
          All signing credentials remain strictly on this computer. App Store FairPlay IPAs cannot be sideloaded.
        </span>
      </div>
    </div>
  );
};
