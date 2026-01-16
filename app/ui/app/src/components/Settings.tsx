import { useState, useCallback } from "react";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Field, Label, Description } from "@/components/ui/fieldset";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import {
  FolderIcon,
  ArrowLeftIcon,
  UserIcon,
  AdjustmentsVerticalIcon,
  SwatchIcon,
  PaintBrushIcon,
  SparklesIcon,
  XMarkIcon,
} from "@heroicons/react/20/solid";
import { Settings as SettingsType } from "@/gotypes";
import { useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getSettings, updateSettings, pullModel } from "@/api";

export default function Settings() {
  const queryClient = useQueryClient();
  const [showSaved, setShowSaved] = useState(false);
  const [restartMessage, setRestartMessage] = useState(false);
  const [avatarTimestamp, setAvatarTimestamp] = useState(Date.now());
  const navigate = useNavigate();
  const [pullModelName, setPullModelName] = useState("");
  const [pullStatus, setPullStatus] = useState<{ status: string; total?: number; completed?: number } | null>(null);
  const [isPulling, setIsPulling] = useState(false);

  const [activeTab, setActiveTab] = useState<"settings" | "personalization" | "general">("personalization");
  const {
    data: settingsData,
    isLoading: loading,
    error,
  } = useQuery({
    queryKey: ["settings"],
    queryFn: getSettings,
  });

  const settings = settingsData?.settings || null;
  const [pendingSettings, setPendingSettings] = useState<SettingsType | null>(null);

  // Sync pendingSettings with loaded settings initially
  if (settings && !pendingSettings && !loading) {
    // We don't want to set state during render, so we rely on the derived state pattern below
    // or just initialize it in a useEffect if strictly necessary. 
    // However, for simplicity here, let's just initialize state lazily.
  }

  // Derived state for display
  const displaySettings = pendingSettings || settings;
  const hasChanges = !!pendingSettings;

  const updateSettingsMutation = useMutation({
    mutationFn: updateSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      setPendingSettings(null); // Clear pending changes on success
      setShowSaved(true);
      setTimeout(() => setShowSaved(false), 1500);
    },
  });

  const handleChange = useCallback(
    (field: keyof SettingsType, value: any) => {
      if (displaySettings) {
        // Special case: Avatar must be saved immediately to be visible via API
        if (field === "avatar_path") {
          const updatedSettings = new SettingsType({
            ...displaySettings,
            [field]: value
          });
          updateSettingsMutation.mutate(updatedSettings);
          // Also update pending if we have other pending changes, or just rely on re-fetch
          if (hasChanges) {
            setPendingSettings(new SettingsType({ ...pendingSettings!, [field]: value }));
          }
          return;
        }

        setPendingSettings(new SettingsType({
          ...displaySettings,
          [field]: value,
        }));

        if (field === "context_length" && value !== settings?.context_length) {
          setRestartMessage(true);
          setTimeout(() => setRestartMessage(false), 3000);
        }
        if (field === "appearance") {
          const root = window.document.documentElement;
          if (value === "dark") {
            root.classList.add("dark");
          } else if (value === "light") {
            root.classList.remove("dark");
          } else {
            if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
              root.classList.add("dark");
            } else {
              root.classList.remove("dark");
            }
          }
        }

        if (field === "primary_color") {
          window.document.documentElement.style.setProperty('--primary-color', value);
        }

        if (field === "accent_color") {
          window.document.documentElement.style.setProperty('--accent-color', value);
        }
      }
    },
    [displaySettings, settings, hasChanges, pendingSettings, updateSettingsMutation],
  );

  const handleSave = () => {
    if (pendingSettings) {
      updateSettingsMutation.mutate(pendingSettings);
    }
  };

  const handleResetToDefaults = () => {
    if (displaySettings) {
      const defaultSettings = new SettingsType({
        expose: false,
        browser: false,
        models: "",
        agent: false,
        tools: false,
        context_length: 4096,
        airplane_mode: false,
        nickname: "",
        avatar_path: "",
        custom_instructions: "",
        appearance: "",
        accent_color: "",
        primary_color: "",
      });
      // For reset, we can either set pending, or save immediately. 
      // User likely expects immediate reset? Or manual save after reset? 
      // Let's set it as pending so they have to click save.
      setPendingSettings(defaultSettings);
    }
  };

  const handlePullModel = async () => {
    if (!pullModelName) return;
    setIsPulling(true);
    setPullStatus({ status: "Starting download..." });
    try {
      for await (const event of pullModel(pullModelName)) {
        setPullStatus(event);
        if (event.status === "success") {
          setPullStatus({ status: "Download complete!" });
          setPullModelName("");
        }
      }
    } catch (err) {
      setPullStatus({ status: `Error: ${err}` });
    } finally {
      setIsPulling(false);
    }
  };

  if (loading) {
    return null;
  }

  if (error || !displaySettings) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-red-500">Failed to load settings</div>
      </div>
    );
  }

  const isWindows = navigator.platform.toLowerCase().includes("win");

  return (
    <main className="flex h-screen w-full flex-col select-none dark:bg-app-bg transition-colors duration-300">
      <header
        className="w-full flex flex-none justify-between h-[52px] py-2.5 items-center border-b border-neutral-200 dark:border-neutral-800 select-none"
        onMouseDown={() => window.drag && window.drag()}
        onDoubleClick={() => window.doubleClick && window.doubleClick()}
      >
        <h1
          className={`${isWindows ? "pl-4" : "pl-24"} flex items-center font-rounded text-md font-medium dark:text-white`}
        >
          {isWindows && (
            <button
              onClick={() => navigate({ to: "/" })}
              className="hover:bg-neutral-100 mr-3 dark:hover:bg-neutral-800 rounded-full p-1.5"
            >
              <ArrowLeftIcon className="w-5 h-5 dark:text-white" />
            </button>
          )}
          Settings
        </h1>
        <div className="flex items-center gap-2 pr-4 no-drag">
          {hasChanges && (
            <Button
              onClick={handleSave}
              disabled={updateSettingsMutation.isPending}
              className="bg-primary text-white hover:bg-primary/90"
            >
              {updateSettingsMutation.isPending ? "Saving..." : "Save Changes"}
            </Button>
          )}
          {!isWindows && (
            <button
              onClick={() => navigate({ to: "/" })}
              className="p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded-full"
            >
              <XMarkIcon className="w-6 h-6 dark:text-white" />
            </button>
          )}
        </div>
      </header>
      <div className="w-full p-0 flex-1 flex flex-col overflow-hidden">
        <div className="flex border-b border-neutral-200 dark:border-neutral-800 px-6">
          <button
            onClick={() => setActiveTab("general")}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === "general"
              ? "border-primary text-primary"
              : "border-transparent text-neutral-500 hover:text-black dark:hover:text-white"
              }`}
          >
            General
          </button>
          <button
            onClick={() => setActiveTab("personalization")}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === "personalization"
              ? "border-primary text-primary"
              : "border-transparent text-neutral-500 hover:text-black dark:hover:text-white"
              }`}
          >
            Personalization
          </button>
          <button
            onClick={() => setActiveTab("settings")}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === "settings"
              ? "border-primary text-primary"
              : "border-transparent text-neutral-500 hover:text-black dark:hover:text-white"
              }`}
          >
            Settings
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 scrollbar-hide">
          <div className="max-w-2xl mx-auto space-y-8">
            {activeTab === "general" && (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <SwatchIcon className="w-5 h-5 text-neutral-400" />
                    Appearance
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                    <Field>
                      <Label>Theme</Label>
                      <Description>Choose how Luna AI looks on your device.</Description>
                      <div className="mt-4 grid grid-cols-3 gap-3">
                        {["light", "dark", "system"].map((theme) => (
                          <button
                            key={theme}
                            onClick={() => handleChange("appearance", theme)}
                            className={`px-4 py-2 text-sm rounded-lg border transition-all capitalize ${displaySettings.appearance === theme
                              ? "border-primary bg-primary/10 text-primary dark:border-primary dark:text-primary font-medium"
                              : "border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 hover:border-neutral-300 dark:hover:border-neutral-600"
                              }`}
                          >
                            {theme}
                          </button>
                        ))}
                      </div>
                    </Field>
                  </div>
                </section>

                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <PaintBrushIcon className="w-5 h-5 text-neutral-400" />
                    Colors & Theory
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm space-y-6">

                    {/* Presets */}
                    <Field>
                      <Label>Color Presets</Label>
                      <Description>Choose a pre-designed color combination.</Description>
                      <div className="mt-4 grid grid-cols-2 gap-3">
                        <button
                          onClick={() => {
                            handleChange("primary_color", "#8b5cf6"); // Violet
                            handleChange("accent_color", "#f472b6"); // Pink
                          }}
                          className="flex items-center gap-3 p-3 rounded-lg border border-neutral-200 dark:border-neutral-700 hover:border-neutral-300 dark:hover:border-neutral-600 transition-all bg-gradient-to-r from-violet-50 to-pink-50 dark:from-violet-900/20 dark:to-pink-900/20"
                        >
                          <div className="flex -space-x-2">
                            <div className="w-6 h-6 rounded-full bg-[#8b5cf6] ring-2 ring-white dark:ring-neutral-800" />
                            <div className="w-6 h-6 rounded-full bg-[#f472b6] ring-2 ring-white dark:ring-neutral-800" />
                          </div>
                          <span className="font-medium text-sm text-neutral-900 dark:text-white">Candy</span>
                        </button>

                        <button
                          onClick={() => {
                            handleChange("primary_color", "#581c87"); // Dark Purple
                            handleChange("accent_color", "#f97316"); // Orange
                          }}
                          className="flex items-center gap-3 p-3 rounded-lg border border-neutral-200 dark:border-neutral-700 hover:border-neutral-300 dark:hover:border-neutral-600 transition-all bg-gradient-to-r from-purple-50 to-orange-50 dark:from-purple-900/20 dark:to-orange-900/20"
                        >
                          <div className="flex -space-x-2">
                            <div className="w-6 h-6 rounded-full bg-[#581c87] ring-2 ring-white dark:ring-neutral-800" />
                            <div className="w-6 h-6 rounded-full bg-[#f97316] ring-2 ring-white dark:ring-neutral-800" />
                          </div>
                          <span className="font-medium text-sm text-neutral-900 dark:text-white">Midnight</span>
                        </button>
                        <button
                          onClick={() => {
                            handleChange("primary_color", "#0f172a"); // Slate 900
                            handleChange("accent_color", "#38bdf8"); // Sky 400
                          }}
                          className="flex items-center gap-3 p-3 rounded-lg border border-neutral-200 dark:border-neutral-700 hover:border-neutral-300 dark:hover:border-neutral-600 transition-all bg-gradient-to-r from-slate-50 to-sky-50 dark:from-slate-900/20 dark:to-sky-900/20"
                        >
                          <div className="flex -space-x-2">
                            <div className="w-6 h-6 rounded-full bg-[#0f172a] ring-2 ring-white dark:ring-neutral-800" />
                            <div className="w-6 h-6 rounded-full bg-[#38bdf8] ring-2 ring-white dark:ring-neutral-800" />
                          </div>
                          <span className="font-medium text-sm text-neutral-900 dark:text-white">Ocean</span>
                        </button>
                        <button
                          onClick={() => {
                            handleChange("primary_color", "#047857"); // Emerald 700
                            handleChange("accent_color", "#facc15"); // Yellow 400
                          }}
                          className="flex items-center gap-3 p-3 rounded-lg border border-neutral-200 dark:border-neutral-700 hover:border-neutral-300 dark:hover:border-neutral-600 transition-all bg-gradient-to-r from-emerald-50 to-yellow-50 dark:from-emerald-900/20 dark:to-yellow-900/20"
                        >
                          <div className="flex -space-x-2">
                            <div className="w-6 h-6 rounded-full bg-[#047857] ring-2 ring-white dark:ring-neutral-800" />
                            <div className="w-6 h-6 rounded-full bg-[#facc15] ring-2 ring-white dark:ring-neutral-800" />
                          </div>
                          <span className="font-medium text-sm text-neutral-900 dark:text-white">Forest</span>
                        </button>
                      </div>
                    </Field>

                    <div className="h-px bg-neutral-200 dark:bg-neutral-700 my-4" />

                    {/* Primary Color */}
                    <Field>
                      <Label>Primary Color</Label>
                      <Description>The main background/header color tone.</Description>
                      <div className="mt-4 flex gap-3 flex-wrap">
                        {[
                          { name: "Slate", value: "#0f172a" },
                          { name: "Blue", value: "#1e3a8a" },
                          { name: "Violet", value: "#5b21b6" },
                          { name: "Emerald", value: "#064e3b" },
                          { name: "Red", value: "#7f1d1d" },
                          { name: "Black", value: "#000000" },
                        ].map((color) => (
                          <button
                            key={color.value}
                            title={color.name}
                            onClick={() => handleChange("primary_color", color.value)}
                            className={`h-8 w-8 rounded-full border-2 transition-transform hover:scale-110 ${displaySettings.primary_color === color.value
                              ? "border-neutral-900 dark:border-white ring-2 ring-offset-2 ring-offset-white dark:ring-offset-neutral-900 ring-neutral-500"
                              : "border-transparent"
                              }`}
                            style={{ backgroundColor: color.value }}
                          />
                        ))}
                        <div className="relative h-8 w-8 overflow-hidden rounded-full border-2 border-neutral-200 dark:border-neutral-700 group hover:scale-110 transition-transform">
                          <input
                            type="color"
                            className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 hover:cursor-pointer w-[150%] h-[150%] p-0 m-0 border-0"
                            value={displaySettings.primary_color || "#000000"}
                            onChange={(e) => handleChange("primary_color", e.target.value)}
                          />
                        </div>
                      </div>
                    </Field>

                    {/* Accent Color */}
                    <Field>
                      <Label>Accent Color</Label>
                      <Description>Used for buttons, switches, and highlights.</Description>
                      <div className="mt-4 flex gap-3 flex-wrap">
                        {[
                          { name: "Blue", value: "#3b82f6" },
                          { name: "Purple", value: "#a855f7" },
                          { name: "Pink", value: "#ec4899" },
                          { name: "Orange", value: "#f97316" },
                          { name: "Emerald", value: "#10b981" },
                        ].map((color) => (
                          <button
                            key={color.value}
                            title={color.name}
                            onClick={() => handleChange("accent_color", color.value)}
                            className={`h-8 w-8 rounded-full border-2 transition-transform hover:scale-110 ${displaySettings.accent_color === color.value
                              ? "border-neutral-900 dark:border-white ring-2 ring-offset-2 ring-offset-white dark:ring-offset-neutral-900 ring-neutral-500"
                              : "border-transparent"
                              }`}
                            style={{ backgroundColor: color.value }}
                          />
                        ))}
                        <div className="relative h-8 w-8 overflow-hidden rounded-full border-2 border-neutral-200 dark:border-neutral-700 group hover:scale-110 transition-transform">
                          <input
                            type="color"
                            className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 hover:cursor-pointer w-[150%] h-[150%] p-0 m-0 border-0"
                            value={displaySettings.accent_color || "#000000"}
                            onChange={(e) => handleChange("accent_color", e.target.value)}
                          />
                        </div>
                      </div>
                    </Field>
                  </div>
                </section>
              </div>
            )}

            {activeTab === "personalization" && (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <UserIcon className="w-5 h-5 text-neutral-400" />
                    Identity
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm space-y-6">
                    <Field>
                      <Label>Nickname</Label>
                      <Description>What should Luna AI call you?</Description>
                      <div className="mt-2">
                        <Input
                          value={displaySettings.nickname || ""}
                          onChange={(e) => handleChange("nickname", e.target.value)}
                          placeholder="e.g. Alex"
                          className="max-w-md"
                        />
                      </div>
                    </Field>

                    <Field>
                      <Label>Profile Picture</Label>
                      <Description>Select a local image for your profile.</Description>
                      <div className="mt-4 flex items-center gap-4">
                        <div className="h-16 w-16 rounded-full bg-neutral-100 dark:bg-neutral-700 overflow-hidden border border-neutral-200 dark:border-neutral-600 flex items-center justify-center">
                          {displaySettings.avatar_path ? (
                            <img
                              src={`/api/v1/avatar?t=${avatarTimestamp}`}
                              alt="Avatar"
                              className="h-full w-full object-cover"
                              onError={(e) => {
                                // Fallback if image fails to load
                                e.currentTarget.style.display = 'none';
                                e.currentTarget.parentElement?.classList.add('fallback-icon');
                              }}
                            />
                          ) : (
                            <UserIcon className="h-8 w-8 text-neutral-400" />
                          )}
                        </div>
                        <Button
                          type="button"
                          color="white"
                          onClick={async () => {
                            if (window.webview?.selectAvatarFile) {
                              const path = await window.webview.selectAvatarFile();
                              if (path) {
                                // Copy the file to local storage for persistence
                                if (window.webview.copyAvatar) {
                                  const localPath = await window.webview.copyAvatar(path);
                                  if (localPath) {
                                    // handleChange will now auto-save this field
                                    handleChange("avatar_path", localPath);
                                    setTimeout(() => setAvatarTimestamp(Date.now()), 100);
                                  }
                                } else {
                                  // Fallback if copyAvatar is not available
                                  handleChange("avatar_path", path);
                                  setTimeout(() => setAvatarTimestamp(Date.now()), 100);
                                }
                              }
                            }
                          }}
                        >
                          Change Picture
                        </Button>
                      </div>
                    </Field>
                  </div>
                </section>

                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <SparklesIcon className="w-5 h-5 text-neutral-400" />
                    Custom Instructions
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                    <Field>
                      <Label>System Instructions</Label>
                      <Description>Guide how Luna AI behaves in every conversation.</Description>
                      <div className="mt-4">
                        <textarea
                          value={displaySettings.custom_instructions || ""}
                          onChange={(e) => handleChange("custom_instructions", e.target.value)}
                          placeholder="e.g. Always be concise, or act as a helpful coding assistant..."
                          className="w-full min-h-[150px] p-3 text-sm rounded-lg bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white transition-all dark:text-white"
                        />
                      </div>
                    </Field>
                  </div>
                </section>
              </div>
            )}

            {activeTab === "settings" && (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <AdjustmentsVerticalIcon className="w-5 h-5 text-neutral-400" />
                    Conversation Settings
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm space-y-6">
                    <Field>
                      <div className="flex items-center justify-between">
                        <div>
                          <Label>Context Length</Label>
                          <Description>How much memory should models use?</Description>
                        </div>
                        <Badge color="zinc">{displaySettings.context_length || 4096}</Badge>
                      </div>
                      <div className="mt-4">
                        <Slider
                          value={displaySettings.context_length || 4096}
                          onChange={(v) => handleChange("context_length", v)}
                          options={[
                            { value: 4096, label: "4k" },
                            { value: 8192, label: "8k" },
                            { value: 16384, label: "16k" },
                            { value: 32768, label: "32k" },
                          ]}
                        />
                      </div>
                    </Field>

                    <Field>
                      <div className="flex items-center justify-between">
                        <div>
                          <Label>Airplane Mode</Label>
                          <Description>Disable all networking for maximum privacy.</Description>
                        </div>
                        <Switch
                          checked={displaySettings.airplane_mode}
                          onChange={(v) => handleChange("airplane_mode", v)}
                        />
                      </div>
                    </Field>
                  </div>
                </section>

                <section>
                  <h3 className="text-lg font-medium mb-4 dark:text-white flex items-center gap-2">
                    <FolderIcon className="w-5 h-5 text-neutral-400" />
                    Storage
                  </h3>
                  <div className="bg-white dark:bg-neutral-800 rounded-xl p-4 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                    <Field>
                      <Label>Model Location</Label>
                      <div className="mt-2 flex gap-2">
                        <Input value={displaySettings.models || ""} readOnly className="flex-1 opacity-60" />
                        <Button
                          type="button"
                          color="white"
                          onClick={async () => {
                            if (window.webview?.selectModelsDirectory) {
                              const dir = await window.webview.selectModelsDirectory();
                              if (dir) handleChange("models", dir);
                            }
                          }}
                        >
                          Browse
                        </Button>
                      </div>
                    </Field>

                    <Field>
                      <Label>Download Model</Label>
                      <Description>Add a new model from the Ollama library.</Description>
                      <div className="mt-2 flex gap-2">
                        <Input
                          placeholder="e.g. llama3"
                          value={pullModelName}
                          onChange={(e) => setPullModelName(e.target.value)}
                          disabled={isPulling}
                        />
                        <Button
                          type="button"
                          color="zinc"
                          onClick={handlePullModel}
                          disabled={isPulling || !pullModelName}
                        >
                          {isPulling ? "Pulling..." : "Pull"}
                        </Button>
                      </div>
                      {pullStatus && (
                        <div className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
                          {pullStatus.status}
                          {pullStatus.total && pullStatus.completed ? ` (${Math.round((pullStatus.completed / pullStatus.total) * 100)}%)` : ""}
                        </div>
                      )}
                    </Field>
                  </div>
                </section>

                <div className="flex justify-center pt-4">
                  <Button type="button" color="zinc" onClick={handleResetToDefaults}>
                    Reset All to Defaults
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Saved indicator */}
        {(showSaved || restartMessage) && (
          <div className="fixed bottom-4 left-1/2 transform -translate-x-1/2 transition-opacity duration-300 z-50">
            <Badge
              color="green"
              className="!bg-green-500 !text-white dark:!bg-green-600"
            >
              Saved
            </Badge>
          </div>
        )}
      </div>
    </main>
  );
}
