import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings } from "@/gotypes";
import { getSettings, updateSettings } from "@/api";
import { useMemo, useCallback } from "react";

// TODO(hoyyeva): remove turboEnabled when we remove Migration logic in useSelectedModel.ts
interface SettingsState {
  turboEnabled: boolean;
  webSearchEnabled: boolean;
  selectedModel: string;
  sidebarOpen: boolean;
  airplaneMode: boolean;
  thinkEnabled: boolean;
  thinkLevel: string;
  appearance: string;
  accentColor: string;
  primaryColor: string;
}

// Type for partial settings updates
type SettingsUpdate = Partial<{
  turbo_enabled: boolean;
  websearch_enabled: boolean;
  think_enabled: boolean;
  think_level: string;
  selected_model: string;
  sidebar_open: boolean;
  appearance: string;
  accent_color: string;
  primary_color: string;
}>;

export function useSettings() {
  const queryClient = useQueryClient();

  // Fetch settings with useQuery
  const { data: settingsData, error } = useQuery({
    queryKey: ["settings"],
    queryFn: getSettings,
  });

  // Update settings with useMutation
  const updateSettingsMutation = useMutation({
    mutationFn: updateSettings,
    onSuccess: () => {
      // Invalidate the query to ensure fresh data
      queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });

  // Extract settings with defaults
  const settings: SettingsState = useMemo(
    () => ({
      turboEnabled: settingsData?.settings?.turbo_enabled ?? false,
      webSearchEnabled: settingsData?.settings?.websearch_enabled ?? false,
      thinkEnabled: settingsData?.settings?.think_enabled ?? false,
      thinkLevel: settingsData?.settings?.think_level ?? "none",
      selectedModel: settingsData?.settings?.selected_model ?? "",
      sidebarOpen: settingsData?.settings?.sidebar_open ?? false,
      airplaneMode: settingsData?.settings?.airplane_mode ?? false,
      appearance: settingsData?.settings?.appearance ?? "system",
      accentColor: settingsData?.settings?.accent_color ?? "#3b82f6", // Default blue-500
      primaryColor: settingsData?.settings?.primary_color ?? "#000000",
    }),
    [settingsData?.settings],
  );

  // Single function to update most settings
  const setSettings = useCallback(
    async (updates: SettingsUpdate) => {
      if (!settingsData?.settings) return;

      const updatedSettings = new Settings({
        ...settingsData.settings,
        ...updates,
      });

      await updateSettingsMutation.mutateAsync(updatedSettings);
    },
    [settingsData?.settings, updateSettingsMutation],
  );

  return useMemo(
    () => ({
      settings,
      settingsData: settingsData?.settings,
      error,
      setSettings,
    }),
    [settings, settingsData?.settings, error, setSettings],
  );
}
