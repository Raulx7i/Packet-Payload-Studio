import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "./store/settings";

describe("settings defaults", () => {
  it("defaults to dark theme with cyan accent and adjustable glassmorphism", () => {
    expect(DEFAULT_SETTINGS.theme).toBe("dark");
    expect(DEFAULT_SETTINGS.accent).toBe("cyan");
    expect(DEFAULT_SETTINGS.transparency).toBe(true);
    expect(DEFAULT_SETTINGS.glassOpacity).toBe(65);
  });
});
