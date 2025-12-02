import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { AVATAR_TYPES } from "./avatar-selector";
import { getUserInitials } from "@/lib/authUtils";
import { Shield } from "lucide-react";

interface UserAvatarProps {
  user?: { firstName?: string; lastName?: string; email?: string; role?: string; profileImageUrl?: string; avatarType?: string };
  size?: "sm" | "md" | "lg";
  showRole?: boolean;
}

export function UserAvatar({ user, size = "md", showRole = false }: UserAvatarProps) {
  const sizeClass = {
    sm: "h-8 w-8",
    md: "h-10 w-10",
    lg: "h-12 w-12",
  }[size];

  const avatar = user?.avatarType ? AVATAR_TYPES.find((a) => a.id === user.avatarType) : null;
  const AvatarIcon = avatar?.icon;

  return (
    <Avatar className={`${sizeClass} border-2 border-blue-200`}>
      <AvatarImage src={user?.profileImageUrl || ""} alt={user?.firstName || "User"} />
      <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white font-bold flex items-center justify-center text-sm">
        {user?.role === "admin" && showRole ? (
          <Shield className="w-5 h-5" />
        ) : AvatarIcon ? (
          <AvatarIcon className={`${size === "sm" ? "w-4 h-4" : size === "md" ? "w-5 h-5" : "w-6 h-6"}`} />
        ) : (
          getUserInitials(user)
        )}
      </AvatarFallback>
    </Avatar>
  );
}
