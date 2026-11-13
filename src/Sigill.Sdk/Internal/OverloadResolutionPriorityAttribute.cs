// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

#if !NET9_0_OR_GREATER
namespace System.Runtime.CompilerServices;

/// <summary>Polyfill for the C# 13 attribute on targets before .NET 9; the compiler recognises it by name.</summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor | AttributeTargets.Property, Inherited = false)]
internal sealed class OverloadResolutionPriorityAttribute(int priority) : Attribute
{
    public int Priority { get; } = priority;
}
#endif
