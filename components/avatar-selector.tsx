import { Users, UserCircle, Zap, Bot, Brain, Heart, Rocket, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

export const AVATAR_TYPES = [
  { id: "user", name: "User", icon: UserCircle, color: "text-blue-500" },
  { id: "avatar", name: "Avatar", icon: Users, color: "text-purple-500" },
  { id: "astronaut", name: "Astronaut", icon: Rocket, color: "text-indigo-500" },
  { id: "bot", name: "Bot", icon: Bot, color: "text-cyan-500" },
  { id: "cat", name: "Cat", icon: Heart, color: "text-pink-500" },
  { id: "dog", name: "Dog", icon: Brain, color: "text-orange-500" },
  { id: "bear", name: "Bear", icon: Zap, color: "text-amber-500" },
  { id: "robot", name: "Robot", icon: Shield, color: "text-slate-500" },
] as const;

interface AvatarSelectorProps {
  value?: string;
  onChange: (value: string) => void;
  label?: string;
}

export function AvatarSelector({ value, onChange, label = "Choose Avatar" }: AvatarSelectorProps) {
  return (
    <div className="space-y-3">
      <label className="text-sm font-medium">{label}</label>
      <div className="grid grid-cols-4 gap-2">
        {AVATAR_TYPES.map((avatar) => {
          const Icon = avatar.icon;
          const isSelected = value === avatar.id;
          return (
            <button
              key={avatar.id}
              onClick={() => onChange(avatar.id)}
              className={cn(
                "p-3 rounded-lg border-2 transition-all flex flex-col items-center gap-1 hover:bg-slate-50",
                isSelected
                  ? "border-blue-500 bg-blue-50"
                  : "border-slate-200 bg-white hover:border-slate-300"
              )}
              title={avatar.name}
            >
              <Icon className={cn("w-5 h-5", avatar.color)} />
              <span className="text-xs text-slate-600">{avatar.name}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function getAvatarIcon(avatarType?: string) {
  const avatar = AVATAR_TYPES.find((a) => a.id === avatarType);
  if (!avatar) return AVATAR_TYPES[0];
  return avatar;
}
