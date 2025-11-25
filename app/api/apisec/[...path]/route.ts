import { NextRequest, NextResponse } from "next/server";

// APIsec uses a SINGLE API endpoint - tenant is determined by the Bearer token
const APISEC_BASE_URL = "https://api.apisecapps.com";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const pathString = "/" + path.join("/");
  const token = request.headers.get("Authorization");

  if (!token) {
    return NextResponse.json(
      { error: "Authorization header required" },
      { status: 401 }
    );
  }

  try {
    const url = `${APISEC_BASE_URL}${pathString}`;
    console.log(`[PROXY] GET ${url}`);

    const response = await fetch(url, {
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    });

    console.log(`[PROXY] Response status: ${response.status}`);

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[PROXY] API error: ${response.status}`, errorText);
      return NextResponse.json(
        { error: `APIsec API error: ${response.status}`, details: errorText },
        { status: response.status }
      );
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("Proxy error:", error);
    return NextResponse.json(
      { error: "Failed to proxy request to APIsec API" },
      { status: 500 }
    );
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const pathString = "/" + path.join("/");
  const token = request.headers.get("Authorization");

  if (!token) {
    return NextResponse.json(
      { error: "Authorization header required" },
      { status: 401 }
    );
  }

  try {
    const body = await request.json();
    const url = `${APISEC_BASE_URL}${pathString}`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return NextResponse.json(
        { error: `APIsec API error: ${response.status}`, details: errorText },
        { status: response.status }
      );
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("Proxy error:", error);
    return NextResponse.json(
      { error: "Failed to proxy request to APIsec API" },
      { status: 500 }
    );
  }
}
