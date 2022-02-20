import sys
from pydantic import BaseModel
from fastapi.encoders import jsonable_encoder
from fastapi import FastAPI

app = FastAPI()

#models
class SubdomainsModel(BaseModel):
    name: list 
class DomainModel(BaseModel):
    name: str 
    generate_worldlist : bool
    
@app.get("/api/get_subs", response_description="Find All Domain's subdomains", response_model=SubdomainsModel)
async def get_subs(input_domain: DomainModel):