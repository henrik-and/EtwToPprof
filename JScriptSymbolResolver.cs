// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

using Microsoft.Windows.EventTracing;

namespace EtwToPprof
{
  internal static class PprofLabelFormatter
  {
    // Formats labels as '<Package>.<SanitizedName>' with zero extra '.', '::', '<', '(', or leading '['
    // so pprof's package extractor groups JavaScript ('JS.'), WebAssembly ('WebAssembly.'), and C++ ('::')
    // into distinct Flame Graph colors.
    public static string SanitizeBody(string s)
    {
      if (string.IsNullOrEmpty(s))
        return "anonymous";
      var sb = new StringBuilder(s.Length);
      for (int i = 0; i < s.Length; i++)
      {
        char c = s[i];
        if (c == '\0') break;
        if (c == '.' || c == '/') sb.Append(':');
        else if (c == '<' || c == '(') sb.Append('[');
        else if (c == '>' || c == ')') sb.Append(']');
        else sb.Append(c);
      }
      return sb.ToString().Replace("::", ":").Trim();
    }

    public static bool IsWasmSymbolName(string fn)
    {
      if (string.IsNullOrEmpty(fn))
        return false;
      return fn.IndexOf("wasm", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public static bool IsJScriptSymbol(string imgName, string imgPath, string fn)
    {
      if (string.IsNullOrEmpty(imgName) || imgName == "$JScriptDynamic$")
        return true;
      if (!string.IsNullOrEmpty(fn) && fn.EndsWith(" 0x0", StringComparison.Ordinal))
        return true;
      string p = !string.IsNullOrEmpty(imgPath) ? imgPath : imgName;
      return p.IndexOf("://", StringComparison.Ordinal) >= 0 ||
             p.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) ||
             p.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
             p.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
             p.StartsWith("about:", StringComparison.OrdinalIgnoreCase) ||
             p.StartsWith("eval", StringComparison.OrdinalIgnoreCase) ||
             p.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
             p.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractShortUrlName(string url)
    {
      if (string.IsNullOrEmpty(url))
        return string.Empty;
      string shortFile = url;
      int q = shortFile.IndexOf('?');
      if (q > 0) shortFile = shortFile.Substring(0, q);
      shortFile = shortFile.TrimEnd('/');
      int slash = shortFile.LastIndexOf('/');
      if (slash >= 0 && slash + 1 < shortFile.Length)
        shortFile = shortFile.Substring(slash + 1);
      return SanitizeBody(shortFile);
    }

    public static string FormatJsOrWasmFromJScript(string rawName, string url, long line)
    {
      string s = (rawName ?? string.Empty).TrimEnd('\0').Trim();
      if (s.EndsWith(" 0x0", StringComparison.Ordinal))
        s = s.Substring(0, s.Length - 4).TrimEnd();
      if (s.StartsWith("[JS] ", StringComparison.Ordinal))
        s = s.Substring(5).TrimStart();
      if (s.StartsWith("JS.", StringComparison.Ordinal))
        s = s.Substring(3);

      if (IsWasmSymbolName(s))
      {
        string body = SanitizeBody(s).Replace("wasm", "Wasm");
        return "WebAssembly." + body;
      }

      string cleanFile = ExtractShortUrlName(url);
      if (string.IsNullOrEmpty(s))
      {
        if (!string.IsNullOrEmpty(cleanFile))
        {
          return line > 0 ? $"JS.[anonymous@{cleanFile}:{line}]" : $"JS.[anonymous@{cleanFile}]";
        }
        return line > 0 ? $"JS.[anonymous:{line}]" : "JS.[anonymous]";
      }

      if (s.StartsWith("-", StringComparison.Ordinal))
      {
        s = !string.IsNullOrEmpty(cleanFile) ? $"[anonymous@{cleanFile}]{s}" : $"[anonymous]{s}";
      }

      return "JS." + SanitizeBody(s);
    }

    public static string FormatNativeWasm(string rawCppOrBuiltinName)
    {
      string s = (rawCppOrBuiltinName ?? string.Empty).TrimEnd('\0').Trim();
      if (s.StartsWith("WebAssembly.", StringComparison.Ordinal))
        return s;
      s = s.Replace("v8::internal::wasm::", "Wasm:")
           .Replace("v8::internal::compiler::turboshaft::", "Turboshaft:")
           .Replace("v8::internal::compiler::", "Compiler:")
           .Replace("v8::internal::", "V8:");
      string body = SanitizeBody(s);
      if (body.IndexOf("Wasm", StringComparison.Ordinal) < 0)
        body = "Wasm:" + body;
      return "WebAssembly." + body;
    }
  }

  internal readonly struct JsMethodSymbol
  {
    public JsMethodSymbol(ulong startAddress, string displayName, string sourceUrl, long line)
    {
      StartAddress = startAddress;
      DisplayName = displayName;
      SourceUrl = sourceUrl;
      Line = line;
    }
    public ulong StartAddress { get; }
    public string DisplayName { get; }
    public string SourceUrl { get; }
    public long Line { get; }
  }

  internal sealed class JScriptSymbolResolver
  {
    public static readonly Guid V8JScriptProviderId = new Guid("57277741-3638-4A4B-BDBA-0AC6E45DA56C");

    private struct RawMethod
    {
      public ulong Start;
      public ulong End;
      public ulong PrefixMaxEnd;
      public long TimestampNanoseconds;
      public int Seq;
      public ulong ScriptContextId;
      public ulong SourceId;
      public long Line;
      public string RawName;
      public string DisplayName;
      public string SourceUrl;
    }

    private readonly Dictionary<(int pid, ulong ctx, ulong srcId), string> sourcesCtx =
        new Dictionary<(int pid, ulong ctx, ulong srcId), string>();
    private readonly Dictionary<(int pid, ulong srcId), string> sourcesPid =
        new Dictionary<(int pid, ulong srcId), string>();
    private readonly Dictionary<int, List<RawMethod>> rawByPid =
        new Dictionary<int, List<RawMethod>>();
    private readonly Dictionary<int, RawMethod[]> methodsByPid =
        new Dictionary<int, RawMethod[]>();
    private int seq;

    public void Register(ITraceProcessor trace)
    {
      trace.UseStreaming().UseUnparsedEvents(
          new[] { V8JScriptProviderId },
          OnUnparsedEvent);
    }

    private void OnUnparsedEvent(EventContext context)
    {
      TraceEvent ev = context.Event;
      if (!ev.HasValue || !ev.IsGeneric)
        return;

      UnparsedGenericEvent ge = ev.AsGenericEvent;
      if (!ge.HasValue || ge.ProviderId != V8JScriptProviderId)
        return;

      ParsePayload(ge.ProcessId, ge.Id, ge.Is32Bit, ge.Timestamp.Nanoseconds, ge.Data);
    }

    internal void ParsePayload(int pid, int id, bool is32Bit, long timestampNs, ReadOnlySpan<byte> data)
    {
      int ptrSize = is32Bit ? 4 : 8;

      if (id == 39 || id == 41)
      {
        int headerLen = 12 + ptrSize;
        if (data.Length < headerLen + 2)
          return;

        ulong srcId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(0, 8));
        ulong ctx = ReadPointer(data.Slice(8, ptrSize), ptrSize);
        string url = ReadUtf16Z(data.Slice(headerLen));
        if (!string.IsNullOrEmpty(url))
        {
          sourcesCtx[(pid, ctx, srcId)] = url;
          sourcesPid[(pid, srcId)] = url;
        }
      }
      else if (id == 5 || id == 9)
      {
        int headerLen = (2 * ptrSize) + 32;
        if (data.Length < headerLen + 2)
          return;

        ulong ctx = ReadPointer(data.Slice(0, ptrSize), ptrSize);
        ulong start = ReadPointer(data.Slice(ptrSize, ptrSize), ptrSize);
        ulong size = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(2 * ptrSize, 8));
        if (start == 0 || size == 0)
          return;

        ulong srcId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice((2 * ptrSize) + 16, 8));
        uint rawLine = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((2 * ptrSize) + 24, 4));
        long line = (rawLine == 0 || rawLine == uint.MaxValue) ? 0 : (long)rawLine;
        string name = ReadUtf16Z(data.Slice(headerLen));

        if (!rawByPid.TryGetValue(pid, out List<RawMethod> list))
        {
          list = new List<RawMethod>();
          rawByPid[pid] = list;
        }

        ulong end = (ulong.MaxValue - start < size) ? ulong.MaxValue : (start + size);
        list.Add(new RawMethod
        {
          Start = start,
          End = end,
          TimestampNanoseconds = timestampNs,
          Seq = ++seq,
          ScriptContextId = ctx,
          SourceId = srcId,
          Line = line,
          RawName = name
        });
      }
    }

    public bool FinalizeIndex()
    {
      if (rawByPid.Count == 0)
        return false;

      int totalMethods = 0;
      foreach (var kvp in rawByPid)
      {
        int pid = kvp.Key;
        RawMethod[] arr = kvp.Value.ToArray();
        Array.Sort(arr, (a, b) =>
        {
          int cmp = a.Start.CompareTo(b.Start);
          return cmp != 0 ? cmp : a.Seq.CompareTo(b.Seq);
        });

        ulong maxEnd = 0;
        for (int i = 0; i < arr.Length; i++)
        {
          if (arr[i].End > maxEnd)
            maxEnd = arr[i].End;
          arr[i].PrefixMaxEnd = maxEnd;

          string url = null;
          if (arr[i].SourceId != 0)
          {
            if (!sourcesCtx.TryGetValue((pid, arr[i].ScriptContextId, arr[i].SourceId), out url))
              sourcesPid.TryGetValue((pid, arr[i].SourceId), out url);
          }
          arr[i].SourceUrl = string.IsNullOrEmpty(url) ? "JavaScript" : url;
          arr[i].DisplayName = PprofLabelFormatter.FormatJsOrWasmFromJScript(arr[i].RawName, url, arr[i].Line);
        }

        methodsByPid[pid] = arr;
        totalMethods += arr.Length;
      }

      rawByPid.Clear();
      Console.WriteLine("Loaded {0:N0} V8/JS JIT method ranges across {1:N0} scripts from ETW.",
                        totalMethods, sourcesPid.Count);
      return true;
    }

    public bool TryResolve(int processId, ulong instructionAddress, TraceTimestamp sampleTime, out JsMethodSymbol symbol)
    {
      return TryResolveNs(processId, instructionAddress, sampleTime.Nanoseconds, out symbol);
    }

    internal bool TryResolveNs(int processId, ulong instructionAddress, long sampleNs, out JsMethodSymbol symbol)
    {
      symbol = default;
      if (!methodsByPid.TryGetValue(processId, out RawMethod[] arr) || arr.Length == 0)
        return false;

      int lo = 0, hi = arr.Length - 1, upper = -1;
      while (lo <= hi)
      {
        int mid = lo + ((hi - lo) >> 1);
        if (arr[mid].Start <= instructionAddress) { upper = mid; lo = mid + 1; }
        else { hi = mid - 1; }
      }
      if (upper < 0)
        return false;

      int bestBefore = -1, bestAny = -1;
      for (int i = upper; i >= 0; i--)
      {
        if (arr[i].PrefixMaxEnd <= instructionAddress)
          break;
        if (instructionAddress >= arr[i].Start && instructionAddress < arr[i].End)
        {
          if (bestAny < 0 || arr[i].Seq > arr[bestAny].Seq)
            bestAny = i;
          if (arr[i].TimestampNanoseconds <= sampleNs &&
              (bestBefore < 0 || arr[i].Seq > arr[bestBefore].Seq))
          {
            bestBefore = i;
          }
        }
      }

      int chosen = bestBefore >= 0 ? bestBefore : bestAny;
      if (chosen < 0)
        return false;

      ref RawMethod m = ref arr[chosen];
      symbol = new JsMethodSymbol(m.Start, m.DisplayName, m.SourceUrl, m.Line);
      return true;
    }

    private static ulong ReadPointer(ReadOnlySpan<byte> span, int ptrSize)
    {
      return ptrSize == 8
          ? BinaryPrimitives.ReadUInt64LittleEndian(span)
          : BinaryPrimitives.ReadUInt32LittleEndian(span);
    }

    private static string ReadUtf16Z(ReadOnlySpan<byte> span)
    {
      int end = 0;
      while (end + 1 < span.Length)
      {
        if (span[end] == 0 && span[end + 1] == 0)
          break;
        end += 2;
      }
      if (end == 0)
        return string.Empty;
      return Encoding.Unicode.GetString(span.Slice(0, end)).Trim();
    }
  }
}
