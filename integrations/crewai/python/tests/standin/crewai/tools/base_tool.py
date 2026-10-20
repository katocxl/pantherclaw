# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""A stand-in for CrewAI 1.15's tool interface, as far as pantherclaw-crewai
and its tests use it (M14 D60: no committed lock contains CrewAI).

It mirrors crewai/tools/base_tool.py: ``BaseTool`` (the fields name,
description, args_schema, result_as_answer, max_usage_count,
current_usage_count and cache_function; ``run`` validates keyword arguments
against args_schema, claims a use and calls ``_run``, running a coroutine it
returns; ``arun`` does the same with ``_arun``, which by default raises
NotImplementedError; ``to_structured_tool`` returns a tool whose ``func`` is
``_run``, which is how a crew calls it), ``Tool`` (``func``; its ``_arun``
raises NotImplementedError for a function that is not async) and the
``tool`` decorator. Pydantic models are replaced by a small schema of the
function's parameters. ``task sdk:crewai-real`` checks this stand-in against
the real CrewAI (test_crewai.StandInTest) and runs the same tests there.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


def _default_cache_function(_args: Any = None, _result: Any = None) -> bool:
    return True


class _Validated:
    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def model_dump(self) -> dict[str, Any]:
        return dict(self._values)


class ArgsSchema:
    """A function's parameters: model_fields, and model_validate refusing
    missing arguments and dropping unknown ones (pydantic's defaults for a tool schema)."""

    def __init__(self, name: str, fields: dict[str, bool]) -> None:
        self.__name__ = name
        # name → required
        self.model_fields = fields

    def model_validate(self, values: dict[str, Any]) -> _Validated:
        missing = [k for k, required in self.model_fields.items() if required and k not in values]
        if missing:
            raise ValueError(f"missing {missing}")
        return _Validated({k: v for k, v in values.items() if k in self.model_fields})

    @classmethod
    def of(cls, fn: Callable[..., Any]) -> ArgsSchema:
        params = inspect.signature(fn).parameters
        return cls(fn.__name__, {n: p.default is inspect.Parameter.empty for n, p in params.items()})


class BaseTool:
    name: str
    description: str

    def __init__(self, *, name: str, description: str, args_schema: ArgsSchema | None = None, result_as_answer: bool = False,
                 max_usage_count: int | None = None, current_usage_count: int = 0,
                 cache_function: Callable[..., bool] = _default_cache_function) -> None:
        self.name, self.description, self.args_schema = name, description, args_schema
        self.result_as_answer, self.max_usage_count, self.current_usage_count = result_as_answer, max_usage_count, current_usage_count
        self.cache_function = cache_function
        self._usage_lock = threading.Lock()

    def _validate_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        if self.args_schema is not None and self.args_schema.model_fields:
            try:
                return self.args_schema.model_validate(kwargs).model_dump()
            except Exception as e:
                raise ValueError(f"Tool '{self.name}' arguments validation failed: {e}") from e
        return kwargs

    def _claim_usage(self) -> str | None:
        with self._usage_lock:
            if self.max_usage_count is not None and self.current_usage_count >= self.max_usage_count:
                return f"Tool '{self.name}' has reached its usage limit of {self.max_usage_count} times and cannot be used anymore."
            self.current_usage_count += 1
            return None

    def run(self, *args: Any, **kwargs: Any) -> Any:
        if not args:
            kwargs = self._validate_kwargs(kwargs)
        limit = self._claim_usage()
        if limit:
            return limit
        result = self._run(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        return result

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        if not args:
            kwargs = self._validate_kwargs(kwargs)
        limit = self._claim_usage()
        if limit:
            return limit
        return await self._arun(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement _arun.")

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def to_structured_tool(self) -> CrewStructuredTool:
        t = CrewStructuredTool(name=self.name, description=self.description, args_schema=self.args_schema, func=self._run,
                               result_as_answer=self.result_as_answer)
        t._original_tool = self
        return t


@dataclass
class CrewStructuredTool:
    name: str
    description: str
    args_schema: Any
    func: Callable[..., Any]
    result_as_answer: bool = False
    _original_tool: Any = None


class Tool(BaseTool):
    def __init__(self, *, func: Callable[..., Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.func = func

    def run(self, *args: Any, **kwargs: Any) -> Any:
        if not args:
            kwargs = self._validate_kwargs(kwargs)
        limit = self._claim_usage()
        if limit:
            return limit
        result = self.func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        return result

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return self.func(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        result = self.func(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        raise NotImplementedError(f"{self.name} does not have an async function.")


def tool(name: str, /, *, result_as_answer: bool = False, max_usage_count: int | None = None) -> Callable[[Callable[..., Any]], Tool]:
    def wrap(fn: Callable[..., Any]) -> Tool:
        if not fn.__doc__:
            raise ValueError("Function must have a docstring")
        return Tool(name=name, description=inspect.getdoc(fn), func=fn, args_schema=ArgsSchema.of(fn),
                    result_as_answer=result_as_answer, max_usage_count=max_usage_count)

    return wrap
