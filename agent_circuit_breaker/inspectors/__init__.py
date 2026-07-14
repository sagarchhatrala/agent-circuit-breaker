"""Inspectors - Domain-specific action analysis."""

from .filesystem import FilesystemInspector
from .command import CommandInspector

__all__ = ["FilesystemInspector", "CommandInspector"]
